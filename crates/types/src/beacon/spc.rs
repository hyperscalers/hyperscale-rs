//! Strong Prefix Consensus (SPC) wire types.
//!
//! SPC drives one slot through a sequence of views. Each view runs an
//! inner [`PcQc3`]-producing PC instance under a distinct domain
//! context; when a view fails (timeout, leader misbehaviour), `f+1`
//! committee members exchange [`SpcEmptyViewMsg`]s reporting their
//! latest verifiable high triple, and `f+1` such messages aggregate
//! into an indirect [`SpcCert`] that skips to a later view while
//! pinning the next leader to a specific [`SpcHighTriple`].
//!
//! These are the wire-form types; verification (multi-sig assembly,
//! domain-context arithmetic, ranking lookups) lives in the beacon
//! crate.

use sbor::prelude::*;

use crate::{
    Bls12381G2Signature, GenesisConfigHash, Hash, PcQc3, PcVector, PositionalBundle, SpcView,
    ValidatorId,
};

/// `(view, value, proof)` — a verifiable high triple.
///
/// Tracked locally as `max_high` by every SPC participant and reported
/// in [`SpcEmptyViewMsg`]s. The `proof` is the round-3 cert from the
/// PC instance that ran in `view` (`view`'s `pc_context` is derived
/// from the slot's SPC context and `view.to_le_bytes()`).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcHighTriple {
    /// View this triple was produced in.
    pub view: SpcView,
    /// High value certified at `view`.
    pub value: PcVector,
    /// Round-3 cert from `view`'s inner PC instance, anchoring `value`.
    pub proof: PcQc3,
}

/// Empty-view message — sent when a participant times out on `view`
/// without observing a leader proposal, reporting their current
/// `max_high` triple so the next leader can build an indirect cert.
///
/// `sig` is the sender's BLS signature over the canonical
/// `(skip_target, EmptyView_tag)` bytes for `view` and
/// `reported.view`. Aggregating `f+1` of these into an
/// [`SpcCert::Indirect`] authorises entry to view `view + 1`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcEmptyViewMsg {
    /// The empty view.
    pub view: SpcView,
    /// Sender's current `max_high` triple.
    pub reported: SpcHighTriple,
    /// Sender's validator id.
    pub signer: ValidatorId,
    /// Sender's BLS signature over the empty-view signing bytes.
    pub sig: Bls12381G2Signature,
}

/// One signer's contribution to an [`SpcCert::Indirect`].
///
/// The signer attested that they observed `view = for_view - 1` as
/// empty and that their `max_high` at the time was `(reported_view,
/// reported_value)` — committed as a hash so the indirect cert points
/// to a *specific* high triple from a *specific* attestor, not any
/// arbitrary valid `PcQc3` at `reported_view`.
///
/// Validator identity is carried positionally by the enclosing
/// [`PositionalBundle`] in [`SpcCert::Indirect::skip_reports`]; the BLS
/// signature is folded into the cert-level
/// [`SpcCert::Indirect::skip_aggregate_sig`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipReport {
    /// View of the signer's `max_high` at the time of the skip.
    pub reported_view: SpcView,
    /// Content hash of the signer's reported high value.
    pub reported_value_hash: Hash,
}

/// Certificate authorising entry into a view, or — as the sole
/// authenticator of a beacon block — a vacuous bootstrap for genesis.
///
/// The three variants:
/// - [`Self::Genesis`] is vacuously valid; the `config_hash` field
///   binds the chain to a specific operator-supplied
///   [`BeaconGenesisConfig`](crate::BeaconGenesisConfig).
/// - [`Self::Direct`] is the previous view's verifiable high output —
///   the simple case where the previous view succeeded.
/// - [`Self::Indirect`] is `f+1` empty-view attestations bundled into
///   an indirect cert — when the previous view failed, the next
///   leader skips ahead by pointing at the maximum-view triple any of
///   the skip signers reported.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub enum SpcCert {
    /// Vacuously-valid bootstrap cert for the genesis block. `config_hash`
    /// is the canonical hash of the operator's `BeaconGenesisConfig`;
    /// verifiers reject any mismatch against the local config so two
    /// operators with different TOMLs can't accidentally interoperate.
    Genesis {
        /// SBOR-canonical hash of `BeaconGenesisConfig`.
        config_hash: GenesisConfigHash,
    },
    /// `cert^dir(prev_view, value, proof)` — the verifiable high
    /// output of `prev_view`, authorising entry to `prev_view + 1`.
    Direct {
        /// View whose output authorises the next view.
        prev_view: SpcView,
        /// Certified high value at `prev_view`.
        value: PcVector,
        /// Round-3 cert anchoring `value` in `prev_view`'s inner PC.
        proof: PcQc3,
    },
    /// `cert^ind(for_view - 1, (target_view, target_value,
    /// target_proof), Σ)` — `f+1` skip statements certify that view
    /// `for_view - 1` was empty; the cert points to a verifiable high
    /// triple at `target_view`, which is the maximum view index
    /// reported in `Σ`.
    Indirect {
        /// View this cert authorises entry to.
        for_view: SpcView,
        /// View of the parent triple — the maximum view in `skip_reports`.
        target_view: SpcView,
        /// Parent triple's high value at `target_view`.
        target_value: PcVector,
        /// Round-3 cert anchoring `target_value` in `target_view`'s
        /// inner PC.
        target_proof: PcQc3,
        /// `Σ` — `f+1` skip statements, paired positionally with the
        /// signers' committee positions via the bundle's bitfield.
        skip_reports: PositionalBundle<SkipReport>,
        /// Different-messages BLS aggregate over each signer's BLS
        /// signature on their canonical skip-target bytes.
        skip_aggregate_sig: Bls12381G2Signature,
    },
}

/// `P_p,w` — the proposal object a leader sends to authorise entry to
/// view `view`. Pairs the cert with the view it authorises.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SpcProposalObject {
    /// View this proposal authorises entry to.
    pub view: SpcView,
    /// Cert backing the authorization.
    pub cert: SpcCert,
}

impl SpcCert {
    /// SBOR-encoded canonical bytes of this cert. Used by SPC
    /// proposal-object hashing to bind the cert into the input vector.
    ///
    /// # Panics
    ///
    /// Never in practice: every field is `BasicSbor` and the enum is
    /// closed, so encoding is total.
    #[must_use]
    pub fn encode_bytes(&self) -> Vec<u8> {
        basic_encode(self).expect("SpcCert SBOR encoding is infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PcQc2, PcSignerLengths, PcValueElement, PcXpProof, SignerBitfield};

    fn sample_pc_qc3() -> PcQc3 {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let qc2 = PcQc2::new(
            PcVector::empty(),
            signers.clone(),
            Bls12381G2Signature([0x11; 96]),
            PcXpProof::Full,
        );
        PcQc3::new(
            PcVector::empty(),
            qc2,
            None,
            None,
            signers,
            PcSignerLengths::Uniform(0),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_pc_vector(len: u8) -> PcVector {
        PcVector::new((0..len).map(|n| PcValueElement::new([n; 32])))
    }

    fn sample_high_triple() -> SpcHighTriple {
        SpcHighTriple {
            view: SpcView::new(3),
            value: sample_pc_vector(2),
            proof: sample_pc_qc3(),
        }
    }

    #[test]
    fn high_triple_sbor_round_trip() {
        let t = sample_high_triple();
        let bytes = basic_encode(&t).unwrap();
        let decoded: SpcHighTriple = basic_decode(&bytes).unwrap();
        assert_eq!(t, decoded);
    }

    #[test]
    fn empty_view_msg_sbor_round_trip() {
        let m = SpcEmptyViewMsg {
            view: SpcView::new(5),
            reported: sample_high_triple(),
            signer: ValidatorId::new(2),
            sig: Bls12381G2Signature([0x44; 96]),
        };
        let bytes = basic_encode(&m).unwrap();
        let decoded: SpcEmptyViewMsg = basic_decode(&bytes).unwrap();
        assert_eq!(m, decoded);
    }

    #[test]
    fn cert_direct_sbor_round_trip() {
        let c = SpcCert::Direct {
            prev_view: SpcView::new(2),
            value: sample_pc_vector(3),
            proof: sample_pc_qc3(),
        };
        let bytes = basic_encode(&c).unwrap();
        let decoded: SpcCert = basic_decode(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn cert_indirect_sbor_round_trip() {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        let reports = vec![
            SkipReport {
                reported_view: SpcView::new(3),
                reported_value_hash: Hash::from_bytes(b"value-a"),
            },
            SkipReport {
                reported_view: SpcView::new(4),
                reported_value_hash: Hash::from_bytes(b"value-b"),
            },
        ];
        let c = SpcCert::Indirect {
            for_view: SpcView::new(5),
            target_view: SpcView::new(4),
            target_value: sample_pc_vector(2),
            target_proof: sample_pc_qc3(),
            skip_reports: PositionalBundle::new(signers, reports),
            skip_aggregate_sig: Bls12381G2Signature([0xCC; 96]),
        };
        let bytes = basic_encode(&c).unwrap();
        let decoded: SpcCert = basic_decode(&bytes).unwrap();
        assert_eq!(c, decoded);
    }

    #[test]
    fn proposal_object_sbor_round_trip() {
        let p = SpcProposalObject {
            view: SpcView::new(2),
            cert: SpcCert::Direct {
                prev_view: SpcView::new(1),
                value: sample_pc_vector(1),
                proof: sample_pc_qc3(),
            },
        };
        let bytes = basic_encode(&p).unwrap();
        let decoded: SpcProposalObject = basic_decode(&bytes).unwrap();
        assert_eq!(p, decoded);
    }
}
