//! Skip-cert / skip-request verification and assembly helpers.
//!
//! `verify_skip_request` checks a single signed request against the
//! active pool. `verify_skip_cert` checks an aggregated cert against
//! the same pool. `build_skip_cert` assembles quorum-many requests
//! into a self-authenticating cert.

use hyperscale_types::{
    BeaconBlockHash, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Epoch,
    NetworkDefinition, SignerBitfield, SkipEpochCert, SkipRequest, ValidatorId,
    aggregate_verify_bls_different_messages, skip_request_message, verify_bls12381_v1,
};

/// Verify a single [`SkipRequest`] against the active pool.
///
/// Checks:
/// - Signer is a member of `active_pool`.
/// - BLS signature verifies under the signer's pubkey over the canonical
///   skip-request signing bytes.
///
/// `request.anchor_hash` and `request.epoch_to_skip` are not validated
/// against any local state — the coordinator gates those at admission
/// time before calling this helper.
#[must_use]
pub fn verify_skip_request(
    request: &SkipRequest,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let Some(signer_pk) = active_pool
        .iter()
        .find(|(id, _)| *id == request.signer())
        .map(|(_, pk)| *pk)
    else {
        return false;
    };
    let msg = skip_request_message(network, &request.anchor_hash(), request.epoch_to_skip());
    verify_bls12381_v1(&msg, &signer_pk, &request.sig())
}

/// Verify a [`SkipEpochCert`] against `active_pool`.
///
/// Returns `true` only when:
/// - `cert.signers().num_validators() == active_pool.len()` — the bitfield
///   must be sized to the current pool; positional indexing breaks if
///   these diverge.
/// - Signer count meets the quorum threshold `⌈2N/3⌉ + 1`.
/// - The aggregate signature verifies under the union of pubkeys at the
///   set bits over the canonical signing bytes
///   `skip_request_message(network, anchor_hash, epoch_to_skip)`.
///
/// Active-pool drift: `active_pool` is the pool *at verification time*.
/// If the active set has shifted between cert signing and verification,
/// drift produces a false-negative rejection rather than a false-positive
/// acceptance, preserving safety.
#[must_use]
pub fn verify_skip_cert(
    cert: &SkipEpochCert,
    network: &NetworkDefinition,
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> bool {
    let pool_size = active_pool.len();
    if cert.signers().num_validators() != pool_size {
        return false;
    }

    let signer_count = cert.signers().count_ones();
    let quorum = (2 * pool_size).div_ceil(3) + 1;
    if signer_count < quorum {
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
    let msg = skip_request_message(network, &cert.anchor_hash(), cert.epoch_to_skip());
    let msgs: Vec<&[u8]> = std::iter::repeat_n(msg.as_slice(), signer_pks.len()).collect();
    aggregate_verify_bls_different_messages(&msgs, &cert.aggregate_sig(), &signer_pks)
}

/// Build and sign a [`SkipRequest`] under `network`'s domain.
#[must_use]
pub fn sign_skip_request(
    sk: &Bls12381G1PrivateKey,
    signer: ValidatorId,
    network: &NetworkDefinition,
    anchor_hash: BeaconBlockHash,
    epoch_to_skip: Epoch,
) -> SkipRequest {
    let msg = skip_request_message(network, &anchor_hash, epoch_to_skip);
    let sig = sk.sign_v1(&msg);
    SkipRequest::new(anchor_hash, epoch_to_skip, signer, sig)
}

/// Assemble a [`SkipEpochCert`] from `requests` against `active_pool`.
///
/// Returns `Some(cert)` when:
/// - All requests share the same `(anchor_hash, epoch_to_skip)`.
/// - The set of distinct signers from `active_pool` meets quorum.
/// - BLS aggregation succeeds.
///
/// Returns `None` if the inputs are inconsistent, sub-quorum, or
/// aggregation fails. The assembled cert is self-verifying via
/// [`verify_skip_cert`].
#[must_use]
pub fn build_skip_cert(
    requests: &[SkipRequest],
    active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
) -> Option<SkipEpochCert> {
    let first = requests.first()?;
    let anchor_hash = first.anchor_hash();
    let epoch_to_skip = first.epoch_to_skip();
    if requests
        .iter()
        .any(|r| r.anchor_hash() != anchor_hash || r.epoch_to_skip() != epoch_to_skip)
    {
        return None;
    }

    let pool_size = active_pool.len();
    let mut signers = SignerBitfield::new(pool_size);
    let mut sigs = Vec::new();
    for request in requests {
        if let Some(pos) = active_pool
            .iter()
            .position(|(id, _)| *id == request.signer())
            && !signers.is_set(pos)
        {
            signers.set(pos);
            sigs.push(request.sig());
        }
    }

    let signer_count = signers.count_ones();
    let quorum = (2 * pool_size).div_ceil(3) + 1;
    if signer_count < quorum {
        return None;
    }

    let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).ok()?;
    Some(SkipEpochCert::new(
        anchor_hash,
        epoch_to_skip,
        signers,
        aggregate_sig,
    ))
}

#[cfg(test)]
mod tests {
    use hyperscale_types::{
        BeaconBlockHash, Bls12381G1PrivateKey, Epoch, Hash, NetworkDefinition,
        bls_keypair_from_seed,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signing_key(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

    /// A pool of `n` validators with deterministic keys.
    fn pool(
        n: u64,
    ) -> (
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
        Vec<Bls12381G1PrivateKey>,
    ) {
        let mut active = Vec::new();
        let mut keys = Vec::new();
        for i in 0..n {
            let sk = signing_key(i);
            active.push((ValidatorId::new(i), sk.public_key()));
            keys.push(sk);
        }
        (active, keys)
    }

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"skip-anchor"))
    }

    #[test]
    fn verify_skip_request_accepts_genuine() {
        let (active, keys) = pool(4);
        let req = sign_skip_request(
            &keys[2],
            ValidatorId::new(2),
            &net(),
            anchor(),
            Epoch::new(5),
        );
        assert!(verify_skip_request(&req, &net(), &active));
    }

    #[test]
    fn verify_skip_request_rejects_unknown_signer() {
        let (active, _keys) = pool(4);
        let outsider = signing_key(99);
        let req = sign_skip_request(
            &outsider,
            ValidatorId::new(99),
            &net(),
            anchor(),
            Epoch::new(5),
        );
        assert!(!verify_skip_request(&req, &net(), &active));
    }

    #[test]
    fn verify_skip_request_rejects_tampered_sig() {
        let (active, keys) = pool(4);
        let mut req = sign_skip_request(
            &keys[2],
            ValidatorId::new(2),
            &net(),
            anchor(),
            Epoch::new(5),
        );
        let mut sig = req.sig();
        sig.0[0] ^= 1;
        req = SkipRequest::new(req.anchor_hash(), req.epoch_to_skip(), req.signer(), sig);
        assert!(!verify_skip_request(&req, &net(), &active));
    }

    /// `build_skip_cert` followed by `verify_skip_cert` round-trips a
    /// quorum-meeting set of requests.
    #[test]
    fn build_then_verify_skip_cert_round_trips() {
        // Pool of 7, quorum = ⌈14/3⌉ + 1 = 5 + 1 = 6.
        let (active, keys) = pool(7);
        let requests: Vec<SkipRequest> = (0..6u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        let cert = build_skip_cert(&requests, &active).expect("quorum met");
        assert_eq!(cert.signer_count(), 6);
        assert!(verify_skip_cert(&cert, &net(), &active));
    }

    #[test]
    fn build_skip_cert_rejects_below_quorum() {
        let (active, keys) = pool(7);
        // 5 signers, quorum is 6.
        let requests: Vec<SkipRequest> = (0..5u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        assert!(build_skip_cert(&requests, &active).is_none());
    }

    #[test]
    fn build_skip_cert_rejects_mixed_anchors() {
        let (active, keys) = pool(7);
        let alt = BeaconBlockHash::from_raw(Hash::from_bytes(b"other-anchor"));
        let mut requests: Vec<SkipRequest> = (0..6u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        // Swap the last request to a different anchor.
        requests[5] = sign_skip_request(&keys[5], ValidatorId::new(5), &net(), alt, Epoch::new(9));
        assert!(build_skip_cert(&requests, &active).is_none());
    }

    #[test]
    fn build_skip_cert_dedupes_repeated_signer() {
        let (active, keys) = pool(7);
        // 6 distinct signers + one duplicate of signer 0 — quorum met
        // exactly when dedup is enforced.
        let mut requests: Vec<SkipRequest> = (0..6u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        requests.push(sign_skip_request(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            anchor(),
            Epoch::new(9),
        ));
        let cert = build_skip_cert(&requests, &active).expect("quorum met");
        assert_eq!(cert.signer_count(), 6);
        assert!(verify_skip_cert(&cert, &net(), &active));
    }

    #[test]
    fn verify_skip_cert_rejects_bitfield_size_mismatch() {
        let (active, keys) = pool(7);
        let requests: Vec<SkipRequest> = (0..7u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        let cert = build_skip_cert(&requests, &active).expect("quorum met");
        // Verify against a shrunken pool — bitfield positional indexing
        // breaks and the cert must be rejected.
        let shrunken: Vec<_> = active.into_iter().take(6).collect();
        assert!(!verify_skip_cert(&cert, &net(), &shrunken));
    }

    #[test]
    fn verify_skip_cert_rejects_tampered_aggregate() {
        let (active, keys) = pool(7);
        let requests: Vec<SkipRequest> = (0..7u64)
            .map(|i| {
                sign_skip_request(
                    &keys[usize::try_from(i).unwrap()],
                    ValidatorId::new(i),
                    &net(),
                    anchor(),
                    Epoch::new(9),
                )
            })
            .collect();
        let cert = build_skip_cert(&requests, &active).expect("quorum met");
        let mut bad_sig = cert.aggregate_sig();
        bad_sig.0[0] ^= 1;
        let tampered = SkipEpochCert::new(
            cert.anchor_hash(),
            cert.epoch_to_skip(),
            cert.signers().clone(),
            bad_sig,
        );
        assert!(!verify_skip_cert(&tampered, &net(), &active));
    }

    /// Two disjoint signer subsets at the same `(anchor, epoch)` both
    /// pass `verify_skip_cert`. This is the load-bearing property that
    /// lets the skip flow tolerate multiple valid certs converging on a
    /// single block hash via the wrapper.
    #[test]
    fn two_disjoint_quorum_subsets_both_verify() {
        // Pool of 10, quorum = ⌈20/3⌉ + 1 = 7 + 1 = 8.
        let (active, keys) = pool(10);
        // The two subsets must each be ≥ 8 in a pool of 10 — they
        // overlap on at least 6, so disjoint isn't literally achievable
        // at quorum=8. Use overlapping-but-distinct subsets instead:
        // {0..=7} and {2..=9}.
        let make_subset = |range: std::ops::Range<u64>| -> Vec<SkipRequest> {
            range
                .map(|i| {
                    sign_skip_request(
                        &keys[usize::try_from(i).unwrap()],
                        ValidatorId::new(i),
                        &net(),
                        anchor(),
                        Epoch::new(9),
                    )
                })
                .collect()
        };
        let subset_a = make_subset(0..8);
        let subset_b = make_subset(2..10);
        let cert_a = build_skip_cert(&subset_a, &active).expect("quorum met");
        let cert_b = build_skip_cert(&subset_b, &active).expect("quorum met");
        assert_ne!(
            cert_a, cert_b,
            "different signer subsets must produce different certs"
        );
        assert!(verify_skip_cert(&cert_a, &net(), &active));
        assert!(verify_skip_cert(&cert_b, &net(), &active));
    }
}
