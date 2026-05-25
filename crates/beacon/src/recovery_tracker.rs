//! Off-chain assembly of [`RecoveryCertificate`]s from observed
//! [`RecoveryRequest`]s.
//!
//! Buckets verified requests by `(anchor_hash, anchor_epoch, round)`
//! and aggregates them into a self-authenticating certificate once the
//! `⌈2N/3⌉ + 1` quorum lands. The coordinator hands the assembled cert
//! to the next `apply_epoch` call, which installs the new committee.
//!
//! Round bookkeeping — which committees have failed across rounds at
//! the same anchor — lives at the coordinator. Callers pass the
//! cumulative `excluded_validators` list when assembling.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconBlockHash, Bls12381G1PublicKey, Bls12381G2Signature, Epoch, RecoveryCertificate,
    RecoveryRequest, RecoveryRound, SignerBitfield, ValidatorId,
};

/// Bucket of observed `(anchor_hash, anchor_epoch, round)` requests.
#[derive(Debug, Default)]
pub struct RecoveryTracker {
    /// Inner map: one signature per `ValidatorId`. Duplicate observes
    /// from the same validator overwrite (BLS sigs over the same
    /// message are byte-identical so this is a no-op in practice).
    observed: BTreeMap<
        (BeaconBlockHash, Epoch, RecoveryRound),
        BTreeMap<ValidatorId, Bls12381G2Signature>,
    >,
}

impl RecoveryTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an already-verified recovery request. Idempotent per
    /// `(anchor, epoch, round, validator)`. Returns `true` if newly
    /// inserted.
    pub fn observe(&mut self, request: &RecoveryRequest) -> bool {
        let bucket = self
            .observed
            .entry((
                request.last_block_hash(),
                request.last_block_epoch(),
                request.recovery_round(),
            ))
            .or_default();
        bucket.insert(request.signer(), request.sig()).is_none()
    }

    /// Try to assemble a cert for `(anchor_hash, anchor_epoch, round)`.
    ///
    /// Returns `Some(cert)` when observed requests from validators in
    /// `active_pool` meet the quorum threshold
    /// `⌈2 × active_pool.len() / 3⌉ + 1`. The bitfield positions are
    /// indexed against `active_pool` in the order it's supplied.
    /// `excluded_validators` is recorded verbatim on the cert — the
    /// coordinator supplies the cumulative dead-committee set from
    /// prior failed rounds at this anchor's epoch.
    ///
    /// Returns `None` if quorum isn't met OR if BLS aggregation of
    /// the contributing signatures fails (a sign one of the observed
    /// sigs was malformed and slipped past the verifier).
    #[must_use]
    pub fn try_assemble(
        &self,
        anchor_hash: BeaconBlockHash,
        anchor_epoch: Epoch,
        round: RecoveryRound,
        active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
        excluded_validators: Vec<ValidatorId>,
    ) -> Option<RecoveryCertificate> {
        let bucket = self.observed.get(&(anchor_hash, anchor_epoch, round))?;

        let pool_size = active_pool.len();
        let mut signers = SignerBitfield::new(pool_size);
        let mut sigs = Vec::with_capacity(bucket.len().min(pool_size));
        for (pos, (vid, _)) in active_pool.iter().enumerate() {
            if let Some(sig) = bucket.get(vid) {
                signers.set(pos);
                sigs.push(*sig);
            }
        }

        let signer_count = signers.count_ones();
        let quorum = (2 * pool_size).div_ceil(3) + 1;
        if signer_count < quorum {
            return None;
        }

        let aggregate_sig = Bls12381G2Signature::aggregate(&sigs, true).ok()?;
        Some(RecoveryCertificate::new(
            anchor_hash,
            anchor_epoch,
            round,
            excluded_validators,
            signers,
            aggregate_sig,
        ))
    }

    /// Drop all buckets at `(anchor_hash, anchor_epoch)` — called by
    /// the coordinator once a cert at this anchor has been applied
    /// and further requests at the anchor are stale.
    pub fn forget_anchor(&mut self, anchor_hash: BeaconBlockHash, anchor_epoch: Epoch) {
        self.observed
            .retain(|(h, e, _), _| *h != anchor_hash || *e != anchor_epoch);
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl RecoveryTracker {
    #[must_use]
    pub fn signer_count(
        &self,
        anchor_hash: BeaconBlockHash,
        anchor_epoch: Epoch,
        round: RecoveryRound,
    ) -> usize {
        self.observed
            .get(&(anchor_hash, anchor_epoch, round))
            .map_or(0, BTreeMap::len)
    }

    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.observed.len()
    }
}

// Tests temporarily removed during cert-as-authenticator refactor; restore in follow-up.
#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        BeaconBlockHash, Bls12381G1PrivateKey, Epoch, Hash, NetworkDefinition, RecoveryRound,
        ValidatorId, bls_keypair_from_seed, recovery_request_message,
    };

    use super::*;

    fn net() -> NetworkDefinition {
        NetworkDefinition::simulator()
    }

    fn signing_key(seed: u64) -> Arc<Bls12381G1PrivateKey> {
        let mut s = [0u8; 32];
        s[..8].copy_from_slice(&seed.to_le_bytes());
        Arc::new(bls_keypair_from_seed(&s))
    }

    /// A pool of `n` validators with deterministic keys. Returns
    /// `(active_pool, signing_keys)` in matching index order.
    fn pool(
        n: u64,
    ) -> (
        Vec<(ValidatorId, Bls12381G1PublicKey)>,
        Vec<Arc<Bls12381G1PrivateKey>>,
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
        BeaconBlockHash::from_raw(Hash::from_bytes(b"anchor"))
    }

    fn signed_request(
        sk: &Bls12381G1PrivateKey,
        validator: ValidatorId,
        anchor_hash: BeaconBlockHash,
        anchor_epoch: Epoch,
        round: RecoveryRound,
    ) -> RecoveryRequest {
        let msg = recovery_request_message(&net(), &anchor_hash, anchor_epoch, round);
        let sig = sk.sign_v1(&msg);
        RecoveryRequest::new(anchor_hash, anchor_epoch, round, validator, sig)
    }

    #[test]
    fn empty_after_new() {
        let t = RecoveryTracker::new();
        assert_eq!(t.bucket_count(), 0);
        assert_eq!(
            t.signer_count(anchor(), Epoch::new(7), RecoveryRound::new(0)),
            0
        );
    }

    #[test]
    fn observe_inserts_and_dedupes() {
        let mut t = RecoveryTracker::new();
        let (_active, keys) = pool(4);
        let req = signed_request(
            &keys[0],
            ValidatorId::new(0),
            anchor(),
            Epoch::new(7),
            RecoveryRound::new(0),
        );
        assert!(t.observe(&req));
        assert_eq!(
            t.signer_count(anchor(), Epoch::new(7), RecoveryRound::new(0)),
            1
        );
        // Same validator + same triple → no new insert.
        assert!(!t.observe(&req));
        assert_eq!(
            t.signer_count(anchor(), Epoch::new(7), RecoveryRound::new(0)),
            1
        );
    }

    #[test]
    fn try_assemble_returns_none_below_quorum() {
        let mut t = RecoveryTracker::new();
        let (active, keys) = pool(4);
        // 4-validator pool → quorum is ⌈8/3⌉+1 = 3+1 = 4. Two
        // sigs is below.
        for (i, sk) in keys.iter().enumerate().take(2) {
            t.observe(&signed_request(
                sk,
                ValidatorId::new(i as u64),
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
            ));
        }
        assert!(
            t.try_assemble(
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
                &active,
                Vec::new(),
            )
            .is_none()
        );
    }

    #[test]
    fn try_assemble_returns_cert_at_quorum_and_passes_verifier() {
        use crate::recovery::verify_recovery_cert;

        let mut t = RecoveryTracker::new();
        let (active, keys) = pool(4);
        // All 4 sign → ≥ quorum.
        for (i, sk) in keys.iter().enumerate() {
            t.observe(&signed_request(
                sk,
                ValidatorId::new(i as u64),
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
            ));
        }
        let cert = t
            .try_assemble(
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
                &active,
                Vec::new(),
            )
            .expect("quorum reached");
        assert_eq!(cert.signer_count(), 4);
        assert_eq!(cert.last_block_hash(), anchor());
        assert_eq!(cert.last_block_epoch(), Epoch::new(7));
        assert_eq!(cert.recovery_round(), RecoveryRound::new(0));
        // The assembled cert verifies under the same active pool —
        // closes the loop with the existing verifier.
        assert!(verify_recovery_cert(&cert, &net(), &active, None));
    }

    #[test]
    fn observed_validators_not_in_active_pool_are_dropped_from_cert() {
        let mut t = RecoveryTracker::new();
        let (active, keys) = pool(4);
        // Sign with a key whose validator id isn't in `active`.
        let outsider = signing_key(99);
        t.observe(&signed_request(
            &outsider,
            ValidatorId::new(99),
            anchor(),
            Epoch::new(7),
            RecoveryRound::new(0),
        ));
        // Plus 4 in-pool sigs to clear quorum.
        for (i, sk) in keys.iter().enumerate() {
            t.observe(&signed_request(
                sk,
                ValidatorId::new(i as u64),
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
            ));
        }
        let cert = t
            .try_assemble(
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
                &active,
                Vec::new(),
            )
            .expect("quorum reached");
        // Only the 4 in-pool signers contribute.
        assert_eq!(cert.signer_count(), 4);
    }

    #[test]
    fn excluded_validators_are_carried_through_verbatim() {
        let mut t = RecoveryTracker::new();
        let (active, keys) = pool(4);
        for (i, sk) in keys.iter().enumerate() {
            t.observe(&signed_request(
                sk,
                ValidatorId::new(i as u64),
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
            ));
        }
        let excluded = vec![ValidatorId::new(50), ValidatorId::new(51)];
        let cert = t
            .try_assemble(
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(0),
                &active,
                excluded.clone(),
            )
            .unwrap();
        let cert_excluded: Vec<ValidatorId> = cert.excluded_validators().iter().copied().collect();
        assert_eq!(cert_excluded, excluded);
    }

    #[test]
    fn forget_anchor_drops_buckets_at_that_anchor() {
        let mut t = RecoveryTracker::new();
        let (_active, keys) = pool(4);
        // Two buckets at the same anchor (different rounds), one at a
        // different anchor.
        for round in 0..2u32 {
            t.observe(&signed_request(
                &keys[0],
                ValidatorId::new(0),
                anchor(),
                Epoch::new(7),
                RecoveryRound::new(round),
            ));
        }
        let other_anchor = BeaconBlockHash::from_raw(Hash::from_bytes(b"other"));
        t.observe(&signed_request(
            &keys[0],
            ValidatorId::new(0),
            other_anchor,
            Epoch::new(7),
            RecoveryRound::new(0),
        ));
        assert_eq!(t.bucket_count(), 3);
        t.forget_anchor(anchor(), Epoch::new(7));
        assert_eq!(t.bucket_count(), 1);
    }
}
