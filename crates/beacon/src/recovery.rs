//! Recovery-cert handling for the beacon chain.
//!
//! Today: [`verify_recovery_equivocation`], the cryptographic predicate
//! that turns a [`RecoveryEquivocation`] into "yes, this validator
//! double-attested." Future work in this module: [`RecoveryCertificate`]
//! verification (signature aggregate against the active-duty pool,
//! quorum threshold, round monotonicity) and the recovery-aware
//! committee sampler that consumes `excluded_validators`.

use hyperscale_types::{
    Bls12381G1PublicKey, CertifiedBeaconBlock, NetworkDefinition, RecoveryCertificate,
    RecoveryEquivocation, SpcCert, ValidatorId, aggregate_verify_bls_different_messages,
    recovery_request_message, spc_context,
};

use crate::spc::verify_block_cert;

/// Verify that a [`RecoveryEquivocation`] is a genuine double-attestation
/// by the named validator:
///
/// 1. They signed a [`RecoveryRequest`](hyperscale_types::RecoveryRequest)
///    claiming `request.last_block_hash` was their latest finalized
///    view at `request.last_block_epoch`.
/// 2. They contributed to a finalized beacon block's SPC cert at an
///    epoch strictly greater than `request.last_block_epoch`.
///
/// `block_committee` is the beacon committee at `ev.block_epoch` (the
/// signer set whose bitfield positions the embedded SPC cert is
/// indexed against). Callers resolve it by walking back to the
/// epoch's state.
#[must_use]
pub fn verify_recovery_equivocation(
    ev: &RecoveryEquivocation,
    network: &NetworkDefinition,
    block_committee: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    if ev.block_epoch <= ev.request.last_block_epoch() {
        return false;
    }
    if ev.request.signer() != ev.validator {
        return false;
    }
    let Some(position) = block_committee
        .iter()
        .position(|(id, _)| *id == ev.validator)
    else {
        return false;
    };
    let validator_pk = block_committee[position].1;

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

    let spc_ctx = spc_context(ev.block_epoch);
    if !verify_block_cert(&ev.block_cert, network, &spc_ctx, block_committee) {
        return false;
    }
    match &ev.block_cert {
        SpcCert::Direct { proof, .. } => proof.all_signers().is_set(position),
        SpcCert::Indirect { skip_reports, .. } => skip_reports.signers().is_set(position),
        SpcCert::Genesis { .. } => false,
    }
}

// ─── RecoveryCertificate verification ──────────────────────────────────────

/// Verify a [`RecoveryCertificate`] against the current active-duty
/// pool.
///
/// `active_pool` is the validators currently in
/// `OnShard { ready: true, .. }` across any shard, paired with their
/// BLS pubkeys, sorted by `ValidatorId` (the enumeration the cert's
/// `signers` bitfield is indexed against). `last_cert` is the most
/// recently applied recovery cert, if any.
///
/// Returns `true` only when:
/// - `cert.signers().num_validators() == active_pool.len()` — the
///   bitfield must be sized to the current pool; positional indexing
///   breaks if these diverge.
/// - Signer count meets the quorum threshold `⌈2 × pool_size / 3⌉ + 1`.
/// - When `last_cert` shares the same anchor (block hash + epoch), the
///   new `recovery_round` is strictly greater. Round monotonicity
///   clears implicitly on anchor change.
/// - The aggregate signature verifies under the union of pubkeys at
///   the set bits, over the canonical signing bytes
///   `recovery_request_message(network, anchor, epoch, round)`.
///
/// The `excluded_validators` size cap is enforced structurally by the
/// `BoundedVec<_, MAX_EXCLUDED_VALIDATORS>` field on
/// `RecoveryCertificate`; the wire decoder rejects oversize lists
/// before they reach this verifier.
///
/// # Active-pool drift
///
/// `active_pool` is the pool *at verification time*. If the active set
/// has shifted between cert signing and verification (a validator
/// jailed or readied in between), the bitfield's positional indices
/// may map to a pool that's a near-superset of the original — the
/// aggregate signature still verifies as long as the signer set
/// hasn't lost any members. Larger drifts produce a false-negative
/// rejection rather than a false-positive acceptance, preserving
/// safety.
#[must_use]
pub fn verify_recovery_cert(
    cert: &RecoveryCertificate,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
    last_cert: Option<&RecoveryCertificate>,
) -> bool {
    let pool_size = active_pool.len();
    if cert.signers().num_validators() != pool_size {
        return false;
    }

    // Quorum threshold: ⌈2N/3⌉ + 1.
    let signer_count = cert.signers().count_ones();
    let quorum = (2 * pool_size).div_ceil(3) + 1;
    if signer_count < quorum {
        return false;
    }

    // Round monotonicity at the anchor.
    if let Some(prev) = last_cert
        && prev.last_block_hash() == cert.last_block_hash()
        && prev.last_block_epoch() == cert.last_block_epoch()
        && cert.recovery_round() <= prev.recovery_round()
    {
        return false;
    }

    let signer_pks: Vec<Bls12381G1PublicKey> = cert
        .signers()
        .set_indices()
        .map(|i| active_pool[i].1)
        .collect();
    if signer_pks.is_empty() {
        return false;
    }
    let msg = recovery_request_message(
        network,
        &cert.last_block_hash(),
        cert.last_block_epoch(),
        cert.recovery_round(),
    );
    let msgs: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), signer_pks.len()).collect();
    aggregate_verify_bls_different_messages(&msgs, &cert.aggregate_sig(), &signer_pks)
}

// ─── Block-selection rule ──────────────────────────────────────────────────

/// Pick the winning [`CertifiedBeaconBlock`] when two valid candidates
/// exist for the same epoch.
///
/// Race source: a slow original committee can finalize a block while a
/// recovery cert is being assembled in parallel. Both blocks pass their
/// own header / aggregate checks, but the chain can only commit one per
/// epoch, and every honest validator must converge on the same choice.
///
/// Selection order:
///
/// 1. A cert-bearing block wins over a no-cert block. The cert is
///    on-chain proof that the active-duty quorum deemed the prior
///    committee's attempt inadequate at this epoch.
/// 2. Among two cert-bearing blocks, the higher [`RecoveryRound`]
///    wins. Within an epoch, recovery rounds chain on failure with
///    cumulative exclusions, so the higher-round cert reflects the
///    fuller picture.
/// 3. Final tie-break: lower [`BeaconBlockHash`]. Deterministic so
///    every honest validator picks the same winner regardless of
///    network-arrival order.
///
/// # Panics
///
/// Panics if `a.epoch() != b.epoch()`. The rule is scoped to
/// same-epoch race resolution; callers must align the candidates'
/// epochs before invoking.
///
/// [`RecoveryRound`]: hyperscale_types::RecoveryRound
/// [`BeaconBlockHash`]: hyperscale_types::BeaconBlockHash
#[must_use]
pub fn select_winning_block<'a>(
    a: &'a CertifiedBeaconBlock,
    b: &'a CertifiedBeaconBlock,
) -> &'a CertifiedBeaconBlock {
    assert_eq!(
        a.epoch(),
        b.epoch(),
        "select_winning_block: cross-epoch comparison",
    );
    match (a.recovery_cert(), b.recovery_cert()) {
        (Some(_), None) => a,
        (None, Some(_)) => b,
        (Some(ca), Some(cb)) => match ca.recovery_round().cmp(&cb.recovery_round()) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => tie_break_by_hash(a, b),
        },
        (None, None) => tie_break_by_hash(a, b),
    }
}

/// Tie-break: lower [`BeaconBlockHash`] wins. Deterministic across
/// replicas.
fn tie_break_by_hash<'a>(
    a: &'a CertifiedBeaconBlock,
    b: &'a CertifiedBeaconBlock,
) -> &'a CertifiedBeaconBlock {
    if a.block_hash() <= b.block_hash() {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlock, BeaconBlockHash, BeaconCert, Bls12381G1PrivateKey, Bls12381G2Signature, Epoch,
        GenesisConfigHash, Hash, PcValueElement, PcVector, RecoveryRequest, RecoveryRound,
        SignerBitfield, SkipEpochCert, SpcCert, SpcView, bls_keypair_from_seed, pc_context,
        spc_context,
    };

    use super::*;
    use crate::pc::{build_qc1, build_qc2, build_qc3, sign_vote1, sign_vote2, sign_vote3};

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

    /// Drive `signer_positions` of `committee`'s keys through one round
    /// each of PC voting and assemble a `Direct` SPC cert. The cert
    /// verifies under `verify_block_cert` against `committee`, and the
    /// signers' bits are set in `proof.all_signers`.
    fn build_direct_cert(
        prev_view: SpcView,
        epoch: Epoch,
        keys: &[Bls12381G1PrivateKey],
        committee: &[(ValidatorId, Bls12381G1PublicKey)],
        signer_positions: &[usize],
    ) -> SpcCert {
        let net = net();
        let spc_ctx = spc_context(epoch);
        let pc_ctx = pc_context(&spc_ctx, prev_view);
        let v_in = PcVector::empty();
        let v1s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote1(&keys[i], committee[i].0, &net, &pc_ctx, v_in.clone()))
            .collect();
        let v1_refs: Vec<&_> = v1s.iter().collect();
        let qc1 = build_qc1(&v1_refs, committee);
        let v2s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote2(&keys[i], committee[i].0, &net, &pc_ctx, qc1.clone()))
            .collect();
        let v2_refs: Vec<&_> = v2s.iter().collect();
        let qc2 = build_qc2(&v2_refs, committee);
        let v3s: Vec<_> = signer_positions
            .iter()
            .map(|&i| sign_vote3(&keys[i], committee[i].0, &net, &pc_ctx, qc2.clone()))
            .collect();
        let v3_refs: Vec<&_> = v3s.iter().collect();
        let qc3 = build_qc3(&v3_refs, committee);
        let value = qc3.x_pe().clone();
        SpcCert::Direct {
            prev_view,
            value,
            proof: qc3,
        }
    }

    /// Build a `(committee, keys)` pair of size `n` using deterministic
    /// keypairs seeded by validator position.
    fn build_committee(
        n: usize,
    ) -> (
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
        Vec<Bls12381G1PrivateKey>,
    ) {
        let keys: Vec<_> = (0..n).map(|i| keypair(i as u64)).collect();
        let committee: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| (ValidatorId::new(i as u64), sk.public_key()))
            .collect();
        (committee, keys)
    }

    /// Build a genuine equivocation: validator at `equivocator_position`
    /// signs both a recovery request at `anchor_epoch` AND contributes
    /// to the `Direct` SPC cert at `block_epoch`. All `n` validators
    /// sign the cert; the equivocator's bit is set positionally.
    fn genuine_equivocation(
        anchor_epoch: u64,
        recovery_round: u32,
        block_epoch: u64,
        equivocator_position: usize,
        n: usize,
    ) -> (
        RecoveryEquivocation,
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
    ) {
        assert!(equivocator_position < n);
        let (committee, keys) = build_committee(n);
        let validator = committee[equivocator_position].0;

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

        // `verify_qc3` requires exactly `n - f` signers. Pick that
        // many positions including the equivocator.
        let f = n.saturating_sub(1) / 3;
        let q = n - f;
        let mut signer_positions: Vec<usize> = (0..n)
            .filter(|p| *p != equivocator_position)
            .take(q - 1)
            .collect();
        signer_positions.push(equivocator_position);
        signer_positions.sort_unstable();
        let block_cert = build_direct_cert(
            SpcView::new(1),
            Epoch::new(block_epoch),
            &keys,
            &committee,
            &signer_positions,
        );

        let ev = RecoveryEquivocation {
            validator,
            request,
            block_epoch: Epoch::new(block_epoch),
            block_cert,
        };
        (ev, committee)
    }

    #[test]
    fn accepts_genuine_equivocation() {
        let (ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
        assert!(verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// `block_epoch <= request.last_block_epoch` means no
    /// contradiction — the validator's request claim and their later
    /// block contribution are consistent.
    #[test]
    fn rejects_no_semantic_contradiction() {
        let (committee, keys) = build_committee(4);
        let validator = committee[2].0;
        let req_msg =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(0));
        let req_sig = keys[2].sign_v1(&req_msg);
        let request = RecoveryRequest::new(
            anchor(),
            Epoch::new(5),
            RecoveryRound::new(0),
            validator,
            req_sig,
        );
        // Block at the same epoch as the request anchor — not strictly
        // greater, so no equivocation. Cert can be any value: epoch
        // gate rejects before crypto.
        let ev = RecoveryEquivocation {
            validator,
            request,
            block_epoch: Epoch::new(5),
            block_cert: SpcCert::Genesis {
                config_hash: GenesisConfigHash::ZERO,
            },
        };
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// `request.signer != validator` is an internally incoherent
    /// equivocation — the named equivocator never signed the request.
    #[test]
    fn rejects_request_signer_mismatch() {
        let (mut ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
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
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// A request signature that doesn't match the validator's pubkey
    /// is rejected. Tampering the sig bytes after signing breaks
    /// verification.
    #[test]
    fn rejects_tampered_request_signature() {
        let (mut ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
        let mut sig = ev.request.sig();
        sig.0[0] ^= 1;
        ev.request = RecoveryRequest::new(
            ev.request.last_block_hash(),
            ev.request.last_block_epoch(),
            ev.request.recovery_round(),
            ev.request.signer(),
            sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// An equivocator absent from `committee` can't be verified — no
    /// pubkey to check the request sig against.
    #[test]
    fn rejects_unknown_validator() {
        let (mut ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
        ev.validator = ValidatorId::new(99);
        // Re-sign the request as the same unknown validator so the
        // signer-mismatch gate passes and the missing-from-committee
        // gate is the actual rejector.
        let req_msg =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(0));
        let req_sig = keypair(99).sign_v1(&req_msg);
        ev.request = RecoveryRequest::new(
            anchor(),
            Epoch::new(5),
            RecoveryRound::new(0),
            ValidatorId::new(99),
            req_sig,
        );
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// A cert that doesn't verify under the cert verifier is rejected,
    /// even when every other gate would otherwise accept.
    #[test]
    fn rejects_invalid_block_cert() {
        let (mut ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
        // Tamper the cert's value so verify_qc3 fails (the claimed
        // `value` no longer matches `proof.x_pe()`).
        if let SpcCert::Direct {
            prev_view, proof, ..
        } = ev.block_cert.clone()
        {
            ev.block_cert = SpcCert::Direct {
                prev_view,
                value: PcVector::new([PcValueElement::new([0xDE; 32])]),
                proof,
            };
        } else {
            panic!("expected Direct cert from fixture");
        }
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// If the equivocator didn't sign the cert (their bit unset in
    /// `proof.all_signers`), the "they signed both" claim doesn't hold.
    #[test]
    fn rejects_validator_bit_unset() {
        let (committee, keys) = build_committee(4);
        let equivocator_position = 2;
        let validator = committee[equivocator_position].0;
        let req_msg =
            recovery_request_message(&net(), &anchor(), Epoch::new(5), RecoveryRound::new(0));
        let req_sig = keys[equivocator_position].sign_v1(&req_msg);
        let request = RecoveryRequest::new(
            anchor(),
            Epoch::new(5),
            RecoveryRound::new(0),
            validator,
            req_sig,
        );
        // Build the cert with the other three signers — the
        // equivocator's bit will be clear in `proof.all_signers`.
        let block_cert = build_direct_cert(
            SpcView::new(1),
            Epoch::new(6),
            &keys,
            &committee,
            &[0, 1, 3],
        );
        let ev = RecoveryEquivocation {
            validator,
            request,
            block_epoch: Epoch::new(6),
            block_cert,
        };
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    /// A `Genesis` cert is never an SPC-finalized block — verifier
    /// rejects regardless of the equivocator's claim.
    #[test]
    fn rejects_genesis_cert() {
        let (mut ev, committee) = genuine_equivocation(5, 0, 6, 2, 4);
        ev.block_cert = SpcCert::Genesis {
            config_hash: GenesisConfigHash::ZERO,
        };
        assert!(!verify_recovery_equivocation(&ev, &net(), &committee));
    }

    // ─── verify_recovery_cert ────────────────────────────────────────────

    /// Build a recovery cert with `signer_count` of `pool_size`
    /// validators signing. Returns the cert and the active pool.
    fn genuine_cert(
        anchor_epoch: u64,
        recovery_round: u32,
        pool_size: usize,
        signer_count: usize,
    ) -> (RecoveryCertificate, Vec<(ValidatorId, Bls12381G1PublicKey)>) {
        assert!(signer_count <= pool_size);
        let (pool, keys) = build_committee(pool_size);

        let msg = recovery_request_message(
            &net(),
            &anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
        );
        let sigs: Vec<Bls12381G2Signature> = keys
            .iter()
            .take(signer_count)
            .map(|sk| sk.sign_v1(&msg))
            .collect();
        let aggregate_sig =
            Bls12381G2Signature::aggregate(&sigs, true).expect("aggregate succeeds");

        let mut signers = SignerBitfield::new(pool_size);
        for i in 0..signer_count {
            signers.set(i);
        }

        let cert = RecoveryCertificate::new(
            anchor(),
            Epoch::new(anchor_epoch),
            RecoveryRound::new(recovery_round),
            Vec::new(),
            signers,
            aggregate_sig,
        );
        (cert, pool)
    }

    #[test]
    fn cert_accepts_genuine_quorum() {
        // Pool of 7, quorum = ⌈14/3⌉ + 1 = 5 + 1 = 6.
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        assert!(verify_recovery_cert(&cert, &net(), &pool, None));
    }

    #[test]
    fn cert_rejects_below_quorum() {
        // Pool of 7, quorum = 6. 5 signers — one short.
        let (cert, pool) = genuine_cert(5, 0, 7, 5);
        assert!(!verify_recovery_cert(&cert, &net(), &pool, None));
    }

    /// Bitfield sized to a different pool than the verifier sees —
    /// positional indexing breaks and the cert must be rejected.
    #[test]
    fn cert_rejects_bitfield_size_mismatch() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        let trimmed: Vec<_> = pool.into_iter().take(6).collect();
        assert!(!verify_recovery_cert(&cert, &net(), &trimmed, None));
    }

    /// A cert at round N for an anchor where the last applied cert was
    /// already at round N (or higher) is rejected — round must strictly
    /// advance to supersede.
    #[test]
    fn cert_rejects_non_monotonic_round_at_same_anchor() {
        let (prev, pool) = genuine_cert(5, 1, 7, 6);
        let (same_round, _) = genuine_cert(5, 1, 7, 6);
        assert!(!verify_recovery_cert(
            &same_round,
            &net(),
            &pool,
            Some(&prev)
        ));
        let (lower_round, _) = genuine_cert(5, 0, 7, 6);
        assert!(!verify_recovery_cert(
            &lower_round,
            &net(),
            &pool,
            Some(&prev)
        ));
    }

    /// Round monotonicity is scoped per-anchor: a round-0 cert at a
    /// new anchor is fine even if a higher-round cert was applied at a
    /// different anchor.
    #[test]
    fn cert_accepts_round_zero_at_different_anchor() {
        let (prev, pool) = genuine_cert(5, 5, 7, 6);
        let (new_anchor, _) = genuine_cert(6, 0, 7, 6);
        assert!(verify_recovery_cert(
            &new_anchor,
            &net(),
            &pool,
            Some(&prev)
        ));
    }

    /// Tampering the aggregate sig bytes breaks verification.
    #[test]
    fn cert_rejects_tampered_aggregate_sig() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        let mut bad_sig = cert.aggregate_sig();
        bad_sig.0[0] ^= 1;
        let tampered = RecoveryCertificate::new(
            cert.last_block_hash(),
            cert.last_block_epoch(),
            cert.recovery_round(),
            Vec::new(),
            cert.signers().clone(),
            bad_sig,
        );
        assert!(!verify_recovery_cert(&tampered, &net(), &pool, None));
    }

    /// Changing the round in the cert body without re-signing produces
    /// a sig over the wrong canonical message — verifier rejects.
    #[test]
    fn cert_rejects_rebadged_round() {
        let (cert, pool) = genuine_cert(5, 0, 7, 6);
        let rebadged = RecoveryCertificate::new(
            cert.last_block_hash(),
            cert.last_block_epoch(),
            RecoveryRound::new(1),
            Vec::new(),
            cert.signers().clone(),
            cert.aggregate_sig(),
        );
        assert!(!verify_recovery_cert(&rebadged, &net(), &pool, None));
    }

    // ─── select_winning_block ────────────────────────────────────────────

    /// Build a `CertifiedBeaconBlock` for `epoch` whose prev-hash is
    /// keyed off `prev_byte` (so two callers can build distinct blocks
    /// at the same epoch with predictable hash ordering). Pairs with a
    /// Skip cert — the selection rule only inspects `recovery_cert`
    /// (wrapper side-data) and the block hash, so the authenticating
    /// cert kind doesn't matter.
    fn block(
        epoch: u64,
        prev_byte: u8,
        recovery_cert: Option<RecoveryCertificate>,
    ) -> CertifiedBeaconBlock {
        let prev_block_hash = BeaconBlockHash::from_raw(Hash::from_bytes(&[prev_byte; 8]));
        let block = BeaconBlock::skip(Epoch::new(epoch), prev_block_hash);
        let skip_cert = SkipEpochCert::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(epoch),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        );
        CertifiedBeaconBlock::new_unchecked(block, BeaconCert::Skip(skip_cert), recovery_cert)
    }

    /// Helper: synthesize a cert at the given round. Signature bytes
    /// are zero — selection doesn't re-verify.
    fn cert(round: u32) -> RecoveryCertificate {
        RecoveryCertificate::new(
            BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor")),
            Epoch::new(0),
            RecoveryRound::new(round),
            Vec::new(),
            SignerBitfield::new(4),
            Bls12381G2Signature([0u8; 96]),
        )
    }

    /// A cert-bearing block wins over a no-cert block at the same epoch
    /// regardless of argument order.
    #[test]
    fn select_cert_bearing_wins_over_no_cert() {
        let with_cert = block(7, 0xAA, Some(cert(0)));
        let no_cert = block(7, 0xBB, None);
        assert_eq!(
            select_winning_block(&with_cert, &no_cert).block_hash(),
            with_cert.block_hash(),
        );
        assert_eq!(
            select_winning_block(&no_cert, &with_cert).block_hash(),
            with_cert.block_hash(),
        );
    }

    /// Among two cert-bearing blocks at the same epoch, the higher
    /// `recovery_round` wins regardless of argument order.
    #[test]
    fn select_higher_round_wins_among_cert_bearing() {
        let round_0 = block(7, 0xAA, Some(cert(0)));
        let round_3 = block(7, 0xBB, Some(cert(3)));
        assert_eq!(
            select_winning_block(&round_0, &round_3).block_hash(),
            round_3.block_hash(),
        );
        assert_eq!(
            select_winning_block(&round_3, &round_0).block_hash(),
            round_3.block_hash(),
        );
    }

    /// Final tie-break: lower block hash wins, regardless of argument
    /// order. The chosen winner is the same block whichever order the
    /// caller supplies.
    #[test]
    fn select_tie_break_by_lower_block_hash() {
        let a = block(7, 0x01, None);
        let b = block(7, 0xFE, None);
        let lower = a.block_hash().min(b.block_hash());
        assert_eq!(select_winning_block(&a, &b).block_hash(), lower);
        assert_eq!(select_winning_block(&b, &a).block_hash(), lower);
    }

    /// Tie on `recovery_round` (both cert-bearing at same round) falls
    /// through to the lower-hash tie-break.
    #[test]
    fn select_tie_break_among_same_round_cert_bearing() {
        let a = block(7, 0x01, Some(cert(2)));
        let b = block(7, 0xFE, Some(cert(2)));
        let lower = a.block_hash().min(b.block_hash());
        assert_eq!(select_winning_block(&a, &b).block_hash(), lower);
        assert_eq!(select_winning_block(&b, &a).block_hash(), lower);
    }

    /// Cross-epoch comparison is a programmer error — the rule is
    /// scoped to same-epoch race resolution.
    #[test]
    #[should_panic(expected = "cross-epoch comparison")]
    fn select_panics_on_cross_epoch() {
        let a = block(7, 0xAA, None);
        let b = block(8, 0xBB, None);
        let _ = select_winning_block(&a, &b);
    }
}
