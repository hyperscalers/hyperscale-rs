//! A verifier that remembers its verdicts.
//!
//! Every host in a simulation shares one verifier, and every host verifies
//! the same quorum certificates, headers and reveals its peers do — so a
//! cluster of twenty hosts pays for one pairing twenty times over. A verdict
//! is a pure function of its inputs, so the second and every later host can
//! read the first's answer instead.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

use hyperscale_types::{
    AggregateError, AggregateSignature, ConsensusPublicKey, ConsensusSignature, Hash, Verifier,
    VrfProof,
};

/// A [`Verifier`] caching every verdict of `V` by a digest of the call.
///
/// Verdicts are kept for the life of the verifier: a signature valid once
/// is valid forever, an invalid one never becomes valid, and a simulation
/// asks about a bounded set of artifacts. [`Verifier::aggregate`] is not a
/// verdict and passes straight through.
pub struct MemoVerifier<V> {
    inner: V,
    verdicts: Mutex<HashMap<Hash, bool>>,
}

impl<V> MemoVerifier<V> {
    /// Wrap `inner`.
    #[must_use]
    pub fn new(inner: V) -> Self {
        Self {
            inner,
            verdicts: Mutex::new(HashMap::new()),
        }
    }

    /// How many distinct calls have been answered so far.
    #[must_use]
    pub fn remembered(&self) -> usize {
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn recall(&self, call: Hash) -> Option<bool> {
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&call)
            .copied()
    }

    fn record(&self, call: Hash, verdict: bool) {
        self.verdicts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(call, verdict);
    }

    fn remember(&self, call: Hash, verify: impl FnOnce(&V) -> bool) -> bool {
        if let Some(verdict) = self.recall(call) {
            return verdict;
        }
        let verdict = verify(&self.inner);
        self.record(call, verdict);
        verdict
    }
}

impl<V: std::fmt::Debug> std::fmt::Debug for MemoVerifier<V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoVerifier")
            .field("inner", &self.inner)
            .field("remembered", &self.remembered())
            .finish_non_exhaustive()
    }
}

/// The digest naming one verification call: a tag for the method, then
/// every input length-prefixed, so two calls collide only when they are
/// the same call.
fn call(tag: &[u8], parts: &[&[u8]]) -> Hash {
    let lengths: Vec<[u8; 8]> = parts
        .iter()
        .map(|part| (part.len() as u64).to_le_bytes())
        .collect();
    let mut framed: Vec<&[u8]> = Vec::with_capacity(1 + 2 * parts.len());
    framed.push(tag);
    for (length, part) in lengths.iter().zip(parts) {
        framed.push(length);
        framed.push(part);
    }
    Hash::from_parts(&framed)
}

fn key_bytes(keys: &[ConsensusPublicKey]) -> Vec<&[u8]> {
    keys.iter().map(|key| key.as_bytes().as_slice()).collect()
}

impl<V: Verifier> Verifier for MemoVerifier<V> {
    fn verify(&self, key: &ConsensusPublicKey, message: &[u8], sig: &ConsensusSignature) -> bool {
        let call = call(b"verify", &[key.as_bytes(), message, sig.as_bytes()]);
        self.remember(call, |inner| inner.verify(key, message, sig))
    }

    fn aggregate(&self, sigs: &[ConsensusSignature]) -> Result<AggregateSignature, AggregateError> {
        self.inner.aggregate(sigs)
    }

    fn verify_aggregate_same_message(
        &self,
        message: &[u8],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        let mut parts: Vec<&[u8]> = vec![message, agg.as_bytes()];
        parts.extend(key_bytes(keys));
        let call = call(b"same-message", &parts);
        self.remember(call, |inner| {
            inner.verify_aggregate_same_message(message, agg, keys)
        })
    }

    fn verify_aggregate_different_messages(
        &self,
        messages: &[&[u8]],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        let mut parts: Vec<&[u8]> = vec![agg.as_bytes()];
        parts.extend_from_slice(messages);
        parts.extend(key_bytes(keys));
        let call = call(b"different-messages", &parts);
        self.remember(call, |inner| {
            inner.verify_aggregate_different_messages(messages, agg, keys)
        })
    }

    fn batch_verify(
        &self,
        messages: &[&[u8]],
        sigs: &[ConsensusSignature],
        keys: &[ConsensusPublicKey],
    ) -> Vec<bool> {
        if messages.len() != sigs.len() || sigs.len() != keys.len() {
            return vec![false; messages.len()];
        }
        let calls: Vec<Hash> = (0..messages.len())
            .map(|i| {
                call(
                    b"verify",
                    &[keys[i].as_bytes(), messages[i], sigs[i].as_bytes()],
                )
            })
            .collect();
        let mut verdicts: Vec<Option<bool>> = calls.iter().map(|c| self.recall(*c)).collect();

        // Only the calls nobody has asked about go to the scheme, as one
        // batch, so its whole-batch fast path still applies to them.
        let misses: Vec<usize> = (0..verdicts.len())
            .filter(|&i| verdicts[i].is_none())
            .collect();
        if !misses.is_empty() {
            let batch_messages: Vec<&[u8]> = misses.iter().map(|&i| messages[i]).collect();
            let batch_sigs: Vec<ConsensusSignature> = misses.iter().map(|&i| sigs[i]).collect();
            let batch_keys: Vec<ConsensusPublicKey> = misses.iter().map(|&i| keys[i]).collect();
            let fresh = self
                .inner
                .batch_verify(&batch_messages, &batch_sigs, &batch_keys);
            for (&i, verdict) in misses.iter().zip(fresh) {
                self.record(calls[i], verdict);
                verdicts[i] = Some(verdict);
            }
        }
        verdicts
            .into_iter()
            .map(|verdict| verdict.unwrap_or(false))
            .collect()
    }

    fn verify_vrf(&self, key: &ConsensusPublicKey, message: &[u8], proof: &VrfProof) -> bool {
        let call = call(b"vrf", &[key.as_bytes(), message, proof.as_bytes()]);
        self.remember(call, |inner| inner.verify_vrf(key, message, proof))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use hyperscale_crypto_mock::{MockSigner, MockVerifier};
    use hyperscale_types::Signer;

    use super::*;

    /// A mock verifier that counts how often the scheme is consulted.
    #[derive(Debug, Default)]
    struct Counting {
        calls: AtomicUsize,
    }

    impl Counting {
        fn consulted(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }

        fn tick(&self) {
            self.calls.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl Verifier for Counting {
        fn verify(
            &self,
            key: &ConsensusPublicKey,
            message: &[u8],
            sig: &ConsensusSignature,
        ) -> bool {
            self.tick();
            MockVerifier.verify(key, message, sig)
        }

        fn aggregate(
            &self,
            sigs: &[ConsensusSignature],
        ) -> Result<AggregateSignature, AggregateError> {
            MockVerifier.aggregate(sigs)
        }

        fn verify_aggregate_same_message(
            &self,
            message: &[u8],
            agg: &AggregateSignature,
            keys: &[ConsensusPublicKey],
        ) -> bool {
            self.tick();
            MockVerifier.verify_aggregate_same_message(message, agg, keys)
        }

        fn verify_aggregate_different_messages(
            &self,
            messages: &[&[u8]],
            agg: &AggregateSignature,
            keys: &[ConsensusPublicKey],
        ) -> bool {
            self.tick();
            MockVerifier.verify_aggregate_different_messages(messages, agg, keys)
        }

        fn batch_verify(
            &self,
            messages: &[&[u8]],
            sigs: &[ConsensusSignature],
            keys: &[ConsensusPublicKey],
        ) -> Vec<bool> {
            self.tick();
            MockVerifier.batch_verify(messages, sigs, keys)
        }

        fn verify_vrf(&self, key: &ConsensusPublicKey, message: &[u8], proof: &VrfProof) -> bool {
            self.tick();
            MockVerifier.verify_vrf(key, message, proof)
        }
    }

    fn signer(seed: u8) -> MockSigner {
        MockSigner::from_seed(&[seed; 32])
    }

    #[test]
    fn a_repeated_verify_consults_the_scheme_once() {
        let memo = MemoVerifier::new(Counting::default());
        let signer = signer(1);
        let sig = signer.sign(b"hello").expect("mock signs");
        for _ in 0..5 {
            assert!(memo.verify(&signer.public_key(), b"hello", &sig));
        }
        assert_eq!(memo.inner.consulted(), 1);
        assert_eq!(memo.remembered(), 1);
    }

    #[test]
    fn a_false_verdict_is_remembered_too() {
        let memo = MemoVerifier::new(Counting::default());
        let signer = signer(1);
        let sig = signer.sign(b"hello").expect("mock signs");
        assert!(!memo.verify(&signer.public_key(), b"other", &sig));
        assert!(!memo.verify(&signer.public_key(), b"other", &sig));
        assert_eq!(memo.inner.consulted(), 1);
    }

    #[test]
    fn a_different_message_is_a_different_call() {
        let memo = MemoVerifier::new(Counting::default());
        let signer = signer(1);
        let sig = signer.sign(b"hello").expect("mock signs");
        assert!(memo.verify(&signer.public_key(), b"hello", &sig));
        assert!(!memo.verify(&signer.public_key(), b"hell", &sig));
        assert_eq!(memo.inner.consulted(), 2);
    }

    #[test]
    fn a_batch_sends_only_unremembered_items_to_the_scheme() {
        let memo = MemoVerifier::new(Counting::default());
        let signers = [signer(1), signer(2), signer(3)];
        let messages: [&[u8]; 3] = [b"a", b"b", b"c"];
        let sigs: Vec<ConsensusSignature> = signers
            .iter()
            .zip(messages)
            .map(|(s, m)| s.sign(m).expect("mock signs"))
            .collect();
        let keys: Vec<ConsensusPublicKey> = signers.iter().map(Signer::public_key).collect();

        assert!(memo.verify(&keys[1], messages[1], &sigs[1]));
        assert_eq!(memo.inner.consulted(), 1);

        assert_eq!(
            memo.batch_verify(&messages, &sigs, &keys),
            vec![true, true, true]
        );
        assert_eq!(
            memo.inner.consulted(),
            2,
            "one batch call for the two misses"
        );
        assert_eq!(memo.remembered(), 3);

        assert_eq!(
            memo.batch_verify(&messages, &sigs, &keys),
            vec![true, true, true]
        );
        assert_eq!(
            memo.inner.consulted(),
            2,
            "a fully remembered batch consults nothing"
        );
    }

    #[test]
    fn a_batch_verdict_and_a_single_verdict_agree() {
        let memo = MemoVerifier::new(Counting::default());
        let signers = [signer(1), signer(2)];
        let good = signers[0].sign(b"a").expect("mock signs");
        let bad = signers[1].sign(b"wrong").expect("mock signs");
        let messages: [&[u8]; 2] = [b"a", b"b"];
        let keys: Vec<ConsensusPublicKey> = signers.iter().map(Signer::public_key).collect();
        assert_eq!(
            memo.batch_verify(&messages, &[good, bad], &keys),
            vec![true, false]
        );
        assert!(!memo.verify(&keys[1], b"b", &bad));
        assert_eq!(memo.inner.consulted(), 1);
    }

    #[test]
    fn a_mismatched_batch_is_all_false_and_remembers_nothing() {
        let memo = MemoVerifier::new(Counting::default());
        let key = signer(1).public_key();
        let messages: [&[u8]; 2] = [b"a", b"b"];
        assert_eq!(
            memo.batch_verify(&messages, &[], &[key]),
            vec![false, false]
        );
        assert_eq!(memo.remembered(), 0);
    }

    #[test]
    fn an_aggregate_verdict_is_remembered_by_its_keys() {
        let memo = MemoVerifier::new(Counting::default());
        let signers = [signer(1), signer(2)];
        let sigs: Vec<ConsensusSignature> = signers
            .iter()
            .map(|s| s.sign(b"m").expect("mock signs"))
            .collect();
        let agg = memo.aggregate(&sigs).expect("two signatures aggregate");
        let keys: Vec<ConsensusPublicKey> = signers.iter().map(Signer::public_key).collect();
        assert!(memo.verify_aggregate_same_message(b"m", &agg, &keys));
        assert!(memo.verify_aggregate_same_message(b"m", &agg, &keys));
        assert!(!memo.verify_aggregate_same_message(b"m", &agg, &keys[..1]));
        assert_eq!(memo.inner.consulted(), 2);
    }

    #[test]
    fn a_vrf_verdict_is_remembered() {
        let memo = MemoVerifier::new(Counting::default());
        let signer = signer(1);
        let proof = signer.vrf_sign(b"seed").expect("mock proves");
        assert!(memo.verify_vrf(&signer.public_key(), b"seed", &proof));
        assert!(memo.verify_vrf(&signer.public_key(), b"seed", &proof));
        assert_eq!(memo.inner.consulted(), 1);
    }
}
