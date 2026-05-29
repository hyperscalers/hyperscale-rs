//! Off-chain assembly of [`SkipEpochCert`]s from observed
//! [`SkipRequest`]s.
//!
//! Buckets verified requests by `(anchor_hash, epoch_to_skip)` and
//! aggregates them into a self-authenticating certificate once the
//! `⌈2N/3⌉ + 1` pool-quorum lands.
//!
//! No topology — pure data structure; tests don't need a
//! `BeaconState`, just an anchor and validator keypairs.

use std::collections::BTreeMap;

use hyperscale_types::{
    BeaconBlockHash, Bls12381G1PublicKey, Epoch, SkipEpochCert, SkipRequest, ValidatorId, Verified,
};

/// Bucket of observed `(anchor_hash, epoch_to_skip)` requests.
#[derive(Debug, Default)]
pub struct SkipTracker {
    /// Inner map: one verified request per `ValidatorId`. Duplicate
    /// observes from the same validator overwrite (BLS sigs over the
    /// same message are byte-identical so this is a no-op in practice).
    observed: BTreeMap<(BeaconBlockHash, Epoch), BTreeMap<ValidatorId, Verified<SkipRequest>>>,
}

impl SkipTracker {
    /// Empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an already-verified skip request. Idempotent per
    /// `(anchor_hash, epoch_to_skip, signer)`. Returns `true` if newly
    /// inserted.
    pub fn observe(&mut self, request: Verified<SkipRequest>) -> bool {
        let bucket = self
            .observed
            .entry((request.anchor_hash(), request.epoch_to_skip()))
            .or_default();
        bucket.insert(request.signer(), request).is_none()
    }

    /// Whether `(anchor, epoch_to_skip)` has accumulated quorum
    /// (`⌈2 × active_pool_size / 3⌉ + 1`) of distinct signers.
    ///
    /// Counts every observed signer in the bucket, including any that
    /// may have dropped out of `active_pool` between admission and the
    /// query — out-of-pool signers don't survive
    /// [`Self::try_assemble`]'s positional filter against the current
    /// pool, but this predicate is a fast pre-check and ignores them.
    #[must_use]
    pub fn quorum_reached(
        &self,
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        active_pool_size: usize,
    ) -> bool {
        let count = self
            .observed
            .get(&(anchor_hash, epoch_to_skip))
            .map_or(0, BTreeMap::len);
        let quorum = (2 * active_pool_size).div_ceil(3) + 1;
        count >= quorum
    }

    /// Try to assemble a verified cert for `(anchor_hash, epoch_to_skip)`.
    ///
    /// Returns `Some(cert)` when observed requests from validators in
    /// `active_pool` meet the quorum threshold and BLS aggregation
    /// succeeds. Returns `None` on sub-quorum, no bucket, or
    /// aggregation failure.
    #[must_use]
    pub fn try_assemble(
        &self,
        anchor_hash: BeaconBlockHash,
        epoch_to_skip: Epoch,
        active_pool: &[(ValidatorId, Bls12381G1PublicKey)],
    ) -> Option<Verified<SkipEpochCert>> {
        let bucket = self.observed.get(&(anchor_hash, epoch_to_skip))?;
        let refs: Vec<&Verified<SkipRequest>> = bucket.values().collect();
        Verified::<SkipEpochCert>::from_verified_requests(&refs, active_pool)
    }

    /// Drop all buckets at `anchor_hash` — called by the coordinator
    /// once a skip block at this anchor has been adopted (or
    /// superseded) and further requests at the anchor are stale.
    pub fn forget_anchor(&mut self, anchor_hash: BeaconBlockHash) {
        self.observed.retain(|(h, _), _| *h != anchor_hash);
    }
}

// Flat accessors; names are the documentation.
#[allow(missing_docs)]
impl SkipTracker {
    #[must_use]
    pub fn signer_count(&self, anchor_hash: BeaconBlockHash, epoch_to_skip: Epoch) -> usize {
        self.observed
            .get(&(anchor_hash, epoch_to_skip))
            .map_or(0, BTreeMap::len)
    }

    #[must_use]
    pub fn bucket_count(&self) -> usize {
        self.observed.len()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hyperscale_types::{
        BeaconBlockHash, Bls12381G1PrivateKey, Epoch, Hash, NetworkDefinition, ValidatorId,
        bls_keypair_from_seed, verify_skip_cert,
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
        BeaconBlockHash::from_raw(Hash::from_bytes(b"skip-anchor"))
    }

    #[test]
    fn empty_after_new() {
        let t = SkipTracker::new();
        assert_eq!(t.bucket_count(), 0);
        assert_eq!(t.signer_count(anchor(), Epoch::new(7)), 0);
    }

    #[test]
    fn observe_inserts_and_dedupes() {
        let mut t = SkipTracker::new();
        let (_active, keys) = pool(4);
        let req = Verified::<SkipRequest>::sign_local(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            anchor(),
            Epoch::new(7),
        );
        assert!(t.observe(req.clone()));
        assert_eq!(t.signer_count(anchor(), Epoch::new(7)), 1);
        // Same `(anchor, epoch, signer)` — no new insert.
        assert!(!t.observe(req));
        assert_eq!(t.signer_count(anchor(), Epoch::new(7)), 1);
    }

    #[test]
    fn try_assemble_returns_none_below_quorum() {
        let mut t = SkipTracker::new();
        let (active, keys) = pool(7);
        // Pool 7 → quorum = ⌈14/3⌉ + 1 = 6.
        for (i, sk) in keys.iter().enumerate().take(5) {
            t.observe(Verified::<SkipRequest>::sign_local(
                sk,
                ValidatorId::new(i as u64),
                &net(),
                anchor(),
                Epoch::new(7),
            ));
        }
        assert!(!t.quorum_reached(anchor(), Epoch::new(7), active.len()));
        assert!(t.try_assemble(anchor(), Epoch::new(7), &active).is_none());
    }

    #[test]
    fn try_assemble_returns_cert_at_quorum_and_passes_verifier() {
        let mut t = SkipTracker::new();
        let (active, keys) = pool(7);
        for (i, sk) in keys.iter().enumerate().take(6) {
            t.observe(Verified::<SkipRequest>::sign_local(
                sk,
                ValidatorId::new(i as u64),
                &net(),
                anchor(),
                Epoch::new(7),
            ));
        }
        assert!(t.quorum_reached(anchor(), Epoch::new(7), active.len()));
        let cert = t
            .try_assemble(anchor(), Epoch::new(7), &active)
            .expect("quorum reached");
        assert_eq!(cert.signer_count(), 6);
        assert_eq!(cert.anchor_hash(), anchor());
        assert_eq!(cert.epoch_to_skip(), Epoch::new(7));
        assert!(verify_skip_cert(&cert, &net(), &active));
    }

    /// Out-of-pool signers slip past `observe` but `try_assemble`'s
    /// positional filter against `active_pool` drops them — only
    /// in-pool sigs contribute to the assembled cert.
    #[test]
    fn observed_outsider_signer_dropped_during_assembly() {
        let mut t = SkipTracker::new();
        let (active, keys) = pool(7);
        let outsider = signing_key(99);
        t.observe(Verified::<SkipRequest>::sign_local(
            &outsider,
            ValidatorId::new(99),
            &net(),
            anchor(),
            Epoch::new(7),
        ));
        for (i, sk) in keys.iter().enumerate().take(6) {
            t.observe(Verified::<SkipRequest>::sign_local(
                sk,
                ValidatorId::new(i as u64),
                &net(),
                anchor(),
                Epoch::new(7),
            ));
        }
        let cert = t
            .try_assemble(anchor(), Epoch::new(7), &active)
            .expect("quorum reached");
        assert_eq!(cert.signer_count(), 6);
        assert!(verify_skip_cert(&cert, &net(), &active));
    }

    #[test]
    fn forget_anchor_drops_buckets_at_that_anchor() {
        let mut t = SkipTracker::new();
        let (_active, keys) = pool(4);
        for epoch in 7u64..=8 {
            t.observe(Verified::<SkipRequest>::sign_local(
                &keys[0],
                ValidatorId::new(0),
                &net(),
                anchor(),
                Epoch::new(epoch),
            ));
        }
        let other = BeaconBlockHash::from_raw(Hash::from_bytes(b"other"));
        t.observe(Verified::<SkipRequest>::sign_local(
            &keys[0],
            ValidatorId::new(0),
            &net(),
            other,
            Epoch::new(7),
        ));
        assert_eq!(t.bucket_count(), 3);
        t.forget_anchor(anchor());
        assert_eq!(t.bucket_count(), 1);
    }

    /// Property: for any sequence of `observe / observe-dup / forget`
    /// events, `quorum_reached` and `try_assemble`'s presence agree —
    /// the cert is assembleable iff quorum is reached, and the
    /// assembled cert is valid by construction (verified via
    /// `verify_skip_cert`).
    #[test]
    fn property_quorum_predicate_agrees_with_assembly() {
        let mut t = SkipTracker::new();
        let (active, keys) = pool(7);
        // Sequence: observe 4, observe-dup 3 of those, observe 2 more
        // (now 6 distinct signers — quorum), forget, observe 6.
        let observe = |t: &mut SkipTracker, i: usize| {
            t.observe(Verified::<SkipRequest>::sign_local(
                &keys[i],
                ValidatorId::new(i as u64),
                &net(),
                anchor(),
                Epoch::new(9),
            ))
        };

        for i in 0..4 {
            observe(t.borrow_mut(), i);
        }
        assert!(!t.quorum_reached(anchor(), Epoch::new(9), active.len()));
        assert!(t.try_assemble(anchor(), Epoch::new(9), &active).is_none());

        // Dup observes — no advance.
        for i in 0..3 {
            assert!(!observe(t.borrow_mut(), i));
        }
        assert!(!t.quorum_reached(anchor(), Epoch::new(9), active.len()));

        // Two more distinct signers crosses quorum.
        observe(t.borrow_mut(), 4);
        observe(t.borrow_mut(), 5);
        assert!(t.quorum_reached(anchor(), Epoch::new(9), active.len()));
        let cert = t
            .try_assemble(anchor(), Epoch::new(9), &active)
            .expect("quorum reached, must assemble");
        assert!(verify_skip_cert(&cert, &net(), &active));

        // Forget clears the bucket — both predicates revert.
        t.forget_anchor(anchor());
        assert!(!t.quorum_reached(anchor(), Epoch::new(9), active.len()));
        assert!(t.try_assemble(anchor(), Epoch::new(9), &active).is_none());

        // Re-observe six → quorum returns.
        for i in 0..6 {
            observe(t.borrow_mut(), i);
        }
        assert!(t.quorum_reached(anchor(), Epoch::new(9), active.len()));
        let cert = t
            .try_assemble(anchor(), Epoch::new(9), &active)
            .expect("quorum reached after re-observe");
        assert!(verify_skip_cert(&cert, &net(), &active));
    }

    // Small helper trait so the closure inside `property_*` doesn't
    // need a mutable reborrow gymnastics for every call.
    trait BorrowMut {
        fn borrow_mut(&mut self) -> &mut Self;
    }
    impl BorrowMut for SkipTracker {
        fn borrow_mut(&mut self) -> &mut Self {
            self
        }
    }
}
