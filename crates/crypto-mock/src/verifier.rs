//! [`Verifier`] over the keyed-hash mock scheme.

use hyperscale_crypto::{
    AggregateError, AggregateSignature, ConsensusPublicKey, ConsensusSignature, VerifiedSignature,
    Verifier, VrfProof,
};

use crate::derive;

/// Mock verification: every check recomputes the expected signature
/// from the public key and compares bytes. Aggregate checks refold the
/// recomputed per-signer signatures in the caller's key order.
#[derive(Debug, Clone, Copy, Default)]
pub struct MockVerifier;

impl Verifier for MockVerifier {
    fn verify(&self, key: &ConsensusPublicKey, message: &[u8], sig: &ConsensusSignature) -> bool {
        derive::signature(key, message) == *sig
    }

    fn aggregate(&self, sigs: &[ConsensusSignature]) -> Result<AggregateSignature, AggregateError> {
        if sigs.is_empty() {
            return Err(AggregateError::Empty);
        }
        // No scheme-level validity to check without the (key, message)
        // pair — a bad input signature surfaces at aggregate verify.
        Ok(derive::aggregate(sigs))
    }

    fn aggregate_verified(
        &self,
        sigs: &[VerifiedSignature],
    ) -> Result<AggregateSignature, AggregateError> {
        let raw: Vec<ConsensusSignature> = sigs.iter().map(VerifiedSignature::signature).collect();
        self.aggregate(&raw)
    }

    fn verify_aggregate_same_message(
        &self,
        message: &[u8],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if keys.is_empty() {
            return false;
        }
        let sigs: Vec<ConsensusSignature> =
            keys.iter().map(|k| derive::signature(k, message)).collect();
        derive::aggregate(&sigs) == *agg
    }

    fn verify_aggregate_different_messages(
        &self,
        messages: &[&[u8]],
        agg: &AggregateSignature,
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if messages.len() != keys.len() || messages.is_empty() {
            return false;
        }
        let sigs: Vec<ConsensusSignature> = keys
            .iter()
            .zip(messages)
            .map(|(k, m)| derive::signature(k, m))
            .collect();
        derive::aggregate(&sigs) == *agg
    }

    fn verify_each(
        &self,
        messages: &[&[u8]],
        sigs: &[ConsensusSignature],
        keys: &[ConsensusPublicKey],
    ) -> bool {
        if messages.is_empty() || messages.len() != sigs.len() || sigs.len() != keys.len() {
            return false;
        }
        messages
            .iter()
            .zip(sigs)
            .zip(keys)
            .all(|((m, s), k)| self.verify(k, m, s))
    }

    fn verify_vrf(&self, key: &ConsensusPublicKey, message: &[u8], proof: &VrfProof) -> bool {
        *derive::signature(key, message).as_bytes() == *proof.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use hyperscale_crypto::{Signer, run_conformance_suite};

    use super::*;
    use crate::MockSigner;

    fn signer(seed_index: u8) -> MockSigner {
        let mut seed = [0u8; 32];
        seed[0] = seed_index;
        MockSigner::from_seed(&seed)
    }

    #[test]
    fn conformance() {
        run_conformance_suite(signer, &MockVerifier);
    }

    /// Ordered fold: permuting the aggregate's inputs (or the key order
    /// at verify) breaks it. Mock-stricter-than-BLS by design — this
    /// enforces the committee-index canonicalization convention, so it
    /// is pinned here rather than in the shared battery (BLS cannot
    /// have it).
    #[test]
    fn aggregate_is_order_sensitive() {
        let signers: Vec<MockSigner> = (0..3).map(signer).collect();
        let keys: Vec<_> = signers.iter().map(Signer::public_key).collect();
        let message = b"order test";
        let sigs: Vec<_> = signers
            .iter()
            .map(|s| s.sign(message).expect("mock sign cannot fail"))
            .collect();

        let agg = MockVerifier.aggregate(&sigs).expect("non-empty");
        assert!(MockVerifier.verify_aggregate_same_message(message, &agg, &keys));

        let mut swapped = keys;
        swapped.swap(0, 1);
        assert!(
            !MockVerifier.verify_aggregate_same_message(message, &agg, &swapped),
            "permuted key order must refold to a different aggregate"
        );

        let mut permuted = sigs;
        permuted.swap(1, 2);
        let permuted_agg = MockVerifier.aggregate(&permuted).expect("non-empty");
        assert_ne!(
            agg, permuted_agg,
            "permuted input signatures must fold to a different aggregate"
        );
    }
}
