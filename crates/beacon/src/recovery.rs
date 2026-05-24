//! Recovery-cert handling for the beacon chain.
//!
//! Today: [`verify_recovery_equivocation`], the cryptographic predicate
//! that turns a [`RecoveryEquivocation`] into "yes, this validator
//! double-attested." Future work in this module: [`RecoveryCertificate`]
//! verification (signature aggregate against the active-duty pool,
//! quorum threshold, round monotonicity) and the recovery-aware
//! committee sampler that consumes `excluded_validators`.

use hyperscale_types::{
    Bls12381G1PublicKey, NetworkDefinition, RecoveryEquivocation, ValidatorId,
    aggregate_verify_bls_different_messages, beacon_block_header_message, recovery_request_message,
};

/// Verify that a [`RecoveryEquivocation`] is a genuine double-attestation
/// by the named validator:
///
/// 1. They signed a [`RecoveryRequest`](hyperscale_types::RecoveryRequest)
///    claiming `request.last_block_hash` was their latest finalized
///    view at `request.last_block_epoch`.
/// 2. They also contributed to the BLS aggregate that finalized
///    `block_header` at a strictly later epoch.
///
/// Returns `true` only when:
/// - `block_header.epoch() > request.last_block_epoch()` (the semantic
///   contradiction — claiming "X is my latest" is incompatible with
///   having signed a later block).
/// - `request.signer() == validator` (the request claims to come from
///   this validator).
/// - The request's signature verifies under the validator's pubkey
///   over the canonical recovery-request signing bytes.
/// - The validator's bit is set in `block_signers` at their position
///   in `lookup`.
/// - The block aggregate signature verifies under the union of pubkeys
///   at the set bits in `block_signers`, indexed positionally against
///   `lookup`.
///
/// # `lookup` indexing convention
///
/// `lookup` is the current validator-set pubkey table — `state.validators`
/// iterated in sorted-id order. The bitfield positions encode an
/// enumeration against the same sorted ordering at the time the block
/// was signed. Validator records persist indefinitely, so the
/// equivocator's position is stable as long as no smaller-id validator
/// has been registered after the block — true under the
/// monotonic-id registration our genesis + admission flow produces.
///
/// Future work: when the active validator set drifts in ways that
/// shuffle positions, the equivocation type needs to commit to the
/// historical committee enumeration directly. Out of scope today.
#[must_use]
pub fn verify_recovery_equivocation(
    ev: &RecoveryEquivocation,
    network: &NetworkDefinition,
    lookup: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    // Semantic contradiction — the block was finalized strictly past
    // the request's anchor epoch.
    if ev.block_header.epoch() <= ev.request.last_block_epoch() {
        return false;
    }
    // Request must claim to come from the named validator.
    if ev.request.signer() != ev.validator {
        return false;
    }
    // Equivocator must be in the current validator set so we can read
    // their pubkey and compute their bitfield position.
    let Some(position) = lookup.iter().position(|(id, _)| *id == ev.validator) else {
        return false;
    };
    let validator_pk = lookup[position].1;

    // Verify the recovery-request signature under the validator's key.
    let req_msg = recovery_request_message(
        network,
        &ev.request.last_block_hash(),
        ev.request.last_block_epoch(),
        ev.request.recovery_round(),
    );
    if !aggregate_verify_bls_different_messages(
        &[req_msg.as_slice()],
        &ev.request.sig(),
        &[validator_pk],
    ) {
        return false;
    }

    // The equivocator's bit must be set; otherwise they didn't sign
    // the block and the claim is incoherent.
    if !ev.block_signers.is_set(position) {
        return false;
    }

    // Reject if the bitfield indexes past the known validator set —
    // structurally invalid evidence (or evidence from a future
    // larger-N set we can't enumerate).
    if ev.block_signers.num_validators() > lookup.len() {
        return false;
    }

    // Verify the block aggregate signature under the union of pubkeys
    // at the set bits.
    let signer_pks: Vec<Bls12381G1PublicKey> = ev
        .block_signers
        .set_indices()
        .map(|i| lookup[i].1)
        .collect();
    if signer_pks.is_empty() {
        return false;
    }
    let block_msg = beacon_block_header_message(network, &ev.block_header);
    let block_msgs: Vec<&[u8]> =
        std::iter::repeat_n(block_msg.as_slice(), signer_pks.len()).collect();
    aggregate_verify_bls_different_messages(&block_msgs, &ev.block_aggregate_sig, &signer_pks)
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlockHash, BeaconBlockHeader, BeaconProposalsRoot, BeaconStateRoot,
        Bls12381G1PrivateKey, Bls12381G2Signature, Epoch, Hash, RecoveryCertHash, RecoveryRequest,
        RecoveryRound, SignerBitfield, bls_keypair_from_seed,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn keypair(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn sample_header(epoch: u64) -> BeaconBlockHeader {
        BeaconBlockHeader::new(
            Epoch::new(epoch),
            BeaconBlockHash::from_raw(Hash::from_bytes(b"prev")),
            BeaconProposalsRoot::from_raw(Hash::from_bytes(b"proposals")),
            BeaconStateRoot::from_raw(Hash::from_bytes(b"state")),
            RecoveryCertHash::ZERO,
        )
    }

    /// Build a genuine equivocation: validator `i` signs both a recovery
    /// request at `anchor_epoch` AND contributes to the BLS aggregate
    /// on `header` (the other signers are validators at the remaining
    /// positions in `lookup`).
    fn genuine_equivocation(
        anchor_epoch: u64,
        recovery_round: u32,
        header_epoch: u64,
        equivocator_position: usize,
        num_validators: usize,
    ) -> (
        RecoveryEquivocation,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        assert!(equivocator_position < num_validators);
        let keys: Vec<Bls12381G1PrivateKey> =
            (0..num_validators).map(|i| keypair(i as u64)).collect();
        let lookup: Vec<(ValidatorId, Bls12381G1PublicKey)> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (ValidatorId::new(i as u64), sk.public_key()))
            .collect();
        let validator = lookup[equivocator_position].0;

        let req_msg = recovery_request_message(
            &net(),
            &anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
        );
        let req_sig = keys[equivocator_position].sign_v1(&req_msg);
        let request = RecoveryRequest::new(
            anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
            validator,
            req_sig,
        );

        let header = sample_header(header_epoch);
        let block_msg = beacon_block_header_message(&net(), &header);
        // All `num_validators` sign — bit set for everyone.
        let block_sigs: Vec<Bls12381G2Signature> =
            keys.iter().map(|sk| sk.sign_v1(&block_msg)).collect();
        let block_aggregate_sig =
            Bls12381G2Signature::aggregate(&block_sigs, true).expect("aggregate succeeds");
        let mut block_signers = SignerBitfield::new(num_validators);
        for i in 0..num_validators {
            block_signers.set(i);
        }

        let ev = RecoveryEquivocation {
            validator,
            request,
            block_header: header,
            block_signers,
            block_aggregate_sig,
        };
        (ev, lookup)
    }

    #[test]
    fn accepts_genuine_equivocation() {
        let (ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        assert!(verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// `block_header.epoch <= request.last_block_epoch` means no
    /// contradiction — the validator's request claim and their later
    /// block contribution are consistent.
    #[test]
    fn rejects_no_semantic_contradiction() {
        // Block at the same epoch as the request anchor — not strictly
        // greater, so no equivocation.
        let (ev, lookup) = genuine_equivocation(5, 0, 5, 2, 4);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// `request.signer != validator` is an internally incoherent
    /// equivocation — the named equivocator never signed the request.
    #[test]
    fn rejects_request_signer_mismatch() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Re-sign a request as validator 3 but keep `ev.validator` at 2.
        let other = ValidatorId::new(3);
        let req_msg =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(0));
        let req_sig = keypair(3).sign_v1(&req_msg);
        ev.request = RecoveryRequest::new(
            anchor(),
            Epoch::new(5),
            RecoveryRound::new(0),
            other,
            req_sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// A request signature that doesn't match the validator's pubkey
    /// is rejected. Tampering the sig bytes after signing breaks
    /// verification.
    #[test]
    fn rejects_tampered_request_signature() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        let mut sig = ev.request.sig();
        sig.0[0] ^= 1;
        ev.request = RecoveryRequest::new(
            ev.request.last_block_hash(),
            ev.request.last_block_epoch(),
            ev.request.recovery_round(),
            ev.request.signer(),
            sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// If the equivocator's bit isn't set in `block_signers`, the
    /// claim "they signed both" doesn't hold internally.
    #[test]
    fn rejects_validator_bit_unset() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        ev.block_signers.clear(2);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// An equivocator absent from `lookup` can't be verified — we have
    /// no pubkey to check the request signature against.
    #[test]
    fn rejects_unknown_validator() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Substitute a validator id that isn't in `lookup`.
        ev.validator = ValidatorId::new(99);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// A block aggregate over the wrong header bytes won't verify.
    #[test]
    fn rejects_tampered_block_header() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Swap the header to a different epoch; the aggregate sig is
        // bound to the original header's bytes.
        ev.block_header = sample_header(10);
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }

    /// Bitfield indexing past the lookup is structurally invalid.
    #[test]
    fn rejects_bitfield_wider_than_lookup() {
        let (mut ev, lookup) = genuine_equivocation(5, 0, 6, 2, 4);
        // Build a wider bitfield (8 slots) — exceeds the 4-validator
        // lookup.
        let mut wide = SignerBitfield::new(8);
        for i in 0..4 {
            wide.set(i);
        }
        ev.block_signers = wide;
        assert!(!verify_recovery_equivocation(&ev, &net(), &lookup));
    }
}
