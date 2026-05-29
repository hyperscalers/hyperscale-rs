//! Beacon-chain skip primitive: per-validator skip attestations and the
//! pool-quorum certificate they assemble into.
//!
//! When the beacon chain stalls past [`SKIP_TIMEOUT`](crate::SKIP_TIMEOUT)
//! at a given anchor, active validators broadcast individually signed
//! [`SkipRequest`]s naming `(anchor_hash, epoch_to_skip)`. Once ⌈2M/3⌉ + 1
//! of the active pool sign the same pair, anyone can aggregate them into
//! a [`SkipEpochCert`] authenticating an empty skip block at
//! `epoch_to_skip`.
//!
//! Cert lives outside the block hash — see
//! [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock). Multiple
//! distinct certs (different signer subsets) at the same
//! `(anchor_hash, epoch_to_skip)` authenticate byte-identical block
//! hashes, so adoption converges.
//!
//! Wire types live up top; the verify / sign / build helpers
//! ([`verify_skip_request`], [`verify_skip_cert`], [`sign_skip_request`],
//! [`build_skip_cert`]) follow. The skip tracker, request pool, and
//! quorum-detection FSM live in the beacon crate — they own per-anchor
//! observation state these pure verifiers don't see.

use sbor::prelude::*;
use thiserror::Error;

use crate::{
    BeaconBlockHash, Bls12381G1PrivateKey, Bls12381G1PublicKey, Bls12381G2Signature, Epoch,
    NetworkDefinition, SignerBitfield, ValidatorId, Verified, Verify,
    aggregate_verify_bls_different_messages, skip_request_message, verify_bls12381_v1,
};

/// One active validator's signed vote that the chain should abandon
/// `epoch_to_skip`.
///
/// Gossiped all-to-all across the active validator pool. ⌈2M/3⌉ + 1
/// signers over the same `(anchor_hash, epoch_to_skip)` pair assemble
/// into a [`SkipEpochCert`].
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipRequest {
    anchor_hash: BeaconBlockHash,
    epoch_to_skip: Epoch,
    signer: ValidatorId,
    sig: Bls12381G2Signature,
}

impl SkipRequest {
    /// Build a `SkipRequest` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        signer: ValidatorId,
        sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch_to_skip,
            signer,
            sig,
        }
    }

    /// Hash of the anchor block the request is pinned to — the latest
    /// finalized block whose epoch immediately precedes
    /// [`Self::epoch_to_skip`].
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch the signer is voting to abandon.
    #[must_use]
    pub const fn epoch_to_skip(&self) -> Epoch {
        self.epoch_to_skip
    }

    /// Validator that signed this request.
    #[must_use]
    pub const fn signer(&self) -> ValidatorId {
        self.signer
    }

    /// BLS signature over the canonical signing message.
    #[must_use]
    pub const fn sig(&self) -> Bls12381G2Signature {
        self.sig
    }

    /// SBOR-encoded canonical bytes of this request. Used as the
    /// content-hash basis for the beacon verification pipeline's
    /// per-request dedup slot.
    ///
    /// # Panics
    ///
    /// Never in practice: every field is `BasicSbor` and the struct is
    /// closed, so encoding is total.
    #[must_use]
    pub fn encode_bytes(&self) -> Vec<u8> {
        basic_encode(self).expect("SkipRequest SBOR encoding is infallible")
    }
}

/// Pool-quorum certificate: ⌈2M/3⌉ + 1 active signers attested that
/// `epoch_to_skip` should be abandoned at the anchor.
///
/// Carried as side-data on a
/// [`CertifiedBeaconBlock`](crate::CertifiedBeaconBlock) — never part
/// of the block hash. Multiple valid certs with different signer
/// subsets all authenticate the same block hash; adoption converges
/// on the unique hash.
///
/// `signers` is positionally indexed against the active validator pool
/// at the anchor's epoch (the same enumeration
/// `derive_active_pool(state)` produces). `aggregate_sig` verifies
/// under the union of the set bits' pubkeys over the canonical
/// skip-request signing bytes for `(anchor_hash, epoch_to_skip)`.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct SkipEpochCert {
    anchor_hash: BeaconBlockHash,
    epoch_to_skip: Epoch,
    signers: SignerBitfield,
    aggregate_sig: Bls12381G2Signature,
}

impl SkipEpochCert {
    /// Build a `SkipEpochCert` from its parts.
    #[must_use]
    pub const fn new(
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        signers: SignerBitfield,
        aggregate_sig: Bls12381G2Signature,
    ) -> Self {
        Self {
            anchor_hash,
            epoch_to_skip,
            signers,
            aggregate_sig,
        }
    }

    /// Anchor block hash the cert is pinned to.
    #[must_use]
    pub const fn anchor_hash(&self) -> BeaconBlockHash {
        self.anchor_hash
    }

    /// Epoch the cert attests should be skipped.
    #[must_use]
    pub const fn epoch_to_skip(&self) -> Epoch {
        self.epoch_to_skip
    }

    /// Bitfield indexing the active pool's positional ordering at the
    /// anchor's epoch.
    #[must_use]
    pub const fn signers(&self) -> &SignerBitfield {
        &self.signers
    }

    /// Aggregated BLS signature over the canonical
    /// `(anchor_hash, epoch_to_skip)` signing bytes, verifying under
    /// the union of [`Self::signers`]' pubkeys.
    #[must_use]
    pub const fn aggregate_sig(&self) -> Bls12381G2Signature {
        self.aggregate_sig
    }

    /// Number of validators contributing to the aggregate.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signers.count_ones()
    }
}

// ─── Verifiers ─────────────────────────────────────────────────────────────

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

// ─── Signing ───────────────────────────────────────────────────────────────

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

// ─── Build ─────────────────────────────────────────────────────────────────

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

// ─── Typestate ─────────────────────────────────────────────────────────────

/// Verification context for [`SkipRequest`] and [`SkipEpochCert`].
///
/// Both predicates resolve signers through the active validator pool
/// at the anchor's epoch. Active-pool drift produces a false-negative
/// rejection rather than a false-positive acceptance — safe at the
/// cost of liveness.
#[derive(Debug, Clone, Copy)]
pub struct SkipVerifyContext<'a> {
    /// Network the signer was bound to.
    pub network: &'a NetworkDefinition,
    /// Active validator pool at verification time. Positional ordering
    /// matches the cert's signer bitfield.
    pub active_pool: &'a [(ValidatorId, Bls12381G1PublicKey)],
}

/// Coarse-grained verification failure for a single skip request.
///
/// Failure modes (signer-not-in-pool, BLS sig check) summarize into
/// one variant; the rejection log line records the specific reason.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SkipRequest verification failed")]
pub struct SkipRequestVerifyError;

/// Coarse-grained verification failure for an aggregated skip cert.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
#[error("SkipEpochCert verification failed")]
pub struct SkipEpochCertVerifyError;

impl Verify<&SkipVerifyContext<'_>> for SkipRequest {
    type Error = SkipRequestVerifyError;

    /// Skip-request predicate: signer is in `active_pool` and the BLS
    /// signature verifies under the signer's pubkey over the canonical
    /// skip-request signing bytes.
    fn verify(&self, ctx: &SkipVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if verify_skip_request(self, ctx.network, ctx.active_pool) {
            Ok(Verified::new_unchecked(self.clone()))
        } else {
            Err(SkipRequestVerifyError)
        }
    }
}

impl Verify<&SkipVerifyContext<'_>> for SkipEpochCert {
    type Error = SkipEpochCertVerifyError;

    /// Skip-cert predicate: signer bitfield matches the active pool's
    /// size, signer count meets `⌈2N/3⌉ + 1`, and the aggregate sig
    /// verifies under the union of the set bits' pubkeys.
    fn verify(&self, ctx: &SkipVerifyContext<'_>) -> Result<Verified<Self>, Self::Error> {
        if verify_skip_cert(self, ctx.network, ctx.active_pool) {
            Ok(Verified::new_unchecked(self.clone()))
        } else {
            Err(SkipEpochCertVerifyError)
        }
    }
}

// ─── Named gates ────────────────────────────────────────────────────────────

impl Verified<SkipRequest> {
    /// Sign a skip request locally. The signer's own BLS sig holds by
    /// definition under the private key, so the produced request is
    /// verified by construction.
    #[must_use]
    pub fn sign_local(
        sk: &Bls12381G1PrivateKey,
        signer: ValidatorId,
        network: &NetworkDefinition,
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
    ) -> Self {
        Self::new_unchecked(sign_skip_request(
            sk,
            signer,
            network,
            anchor_hash,
            epoch_to_skip,
        ))
    }
}

impl Verified<SkipEpochCert> {
    /// Aggregate a quorum-meeting set of verified skip requests into a
    /// verified [`SkipEpochCert`]. Mirror of
    /// [`Verified::<PcQc1>::from_verified_votes`]; returns `None` on the
    /// same conditions as [`build_skip_cert`].
    #[must_use]
    pub fn from_verified_requests(
        requests: &[&Verified<SkipRequest>],
        active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Option<Self> {
        let raw: Vec<SkipRequest> = requests.iter().map(|r| (*r).as_ref().clone()).collect();
        build_skip_cert(&raw, active_pool).map(Self::new_unchecked)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Hash;

    fn anchor() -> BeaconBlockHash {
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn sample_request() -> SkipRequest {
        SkipRequest::new(
            anchor(),
            Epoch::new(7),
            ValidatorId::new(3),
            Bls12381G2Signature([0x33; 96]),
        )
    }

    fn sample_cert() -> SkipEpochCert {
        let mut signers = SignerBitfield::new(4);
        signers.set(0);
        signers.set(1);
        signers.set(2);
        SkipEpochCert::new(
            anchor(),
            Epoch::new(7),
            signers,
            Bls12381G2Signature([0x22; 96]),
        )
    }

    #[test]
    fn request_sbor_round_trip() {
        let original = sample_request();
        let bytes = basic_encode(&original).unwrap();
        let decoded: SkipRequest = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_sbor_round_trip() {
        let original = sample_cert();
        let bytes = basic_encode(&original).unwrap();
        let decoded: SkipEpochCert = basic_decode(&bytes).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn cert_signer_count_reflects_bitfield() {
        assert_eq!(sample_cert().signer_count(), 3);
    }

    // ─── Verifier / builder tests ──────────────────────────────────────

    use crate::bls_keypair_from_seed;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signing_key(seed: u64) -> Bls12381G1PrivateKey {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        bls_keypair_from_seed(&s)
    }

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
